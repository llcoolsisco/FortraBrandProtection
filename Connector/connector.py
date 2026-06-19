### Version2
from SiemplifyConnectors import SiemplifyConnectorExecution
from SiemplifyConnectorsDataModel import AlertInfo
from SiemplifyUtils import output_handler, unix_now

import requests
import json

# =========================================================
# CONFIG
# =========================================================

CONNECTOR_NAME = "FortraBrandProtectionConnector"

VENDOR = "Fortra"
PRODUCT = "Brand Protection"
RULE_GENERATOR = "Fortra Brand Protection Incident"

TOKEN_URL = "https://platform.fortra.com/idp/realms/products/protocol/openid-connect/token"
INCIDENT_SEARCH_URL = "https://platform.fortra.com/bp/api/v1/incident/search"

# =========================================================
# AUTH
# =========================================================

def generate_bearer_token(client_id, client_secret, verify_ssl=True):

    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }

    payload = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret
    }

    response = requests.post(
        TOKEN_URL,
        headers=headers,
        data=payload,
        verify=verify_ssl,
        timeout=60
    )

    if response.status_code != 200:
        raise Exception(f"Auth failed: {response.text}")

    return response.json().get("access_token")


# =========================================================
# FETCH INCIDENTS
# =========================================================

def get_incidents(token,
                  page_number,
                  page_size,
                  statuses,
                  severities,
                  verify_ssl=True):

    headers = {
        "accept": "application/json",
        "Authorization": f"Bearer {token}"
    }

    if isinstance(statuses, str):
        statuses = [s.strip() for s in statuses.split(",") if s.strip()]

    if isinstance(severities, str):
        severities = [s.strip() for s in severities.split(",") if s.strip()]

    params = [
        ("PageNumber", page_number),
        ("PageSize", page_size)
    ]

    # Multi-status support
    for status in statuses:
        params.append(("IncidentStatusCodes", status))

    # Multi-severity support
    for severity in severities:
        params.append(("SeverityCodes", severity))

    response = requests.get(
        INCIDENT_SEARCH_URL,
        headers=headers,
        params=params,
        verify=verify_ssl,
        timeout=60
    )

    if response.status_code != 200:
        raise Exception(f"Incident fetch failed: {response.text}")

    return response.json()


# =========================================================
# HTML WIDGET
# =========================================================

def build_html_widget(incident, urls):

    return f"""
    <div style="font-family:Arial; padding:10px; border:1px solid #ddd;">
        <h3>Fortra Incident</h3>

        <b>Incident ID:</b> {incident.get("incidentId")}<br>
        <b>Incident Number:</b> {incident.get("incidentNumber")}<br>
        <b>Status:</b> {incident.get("status")}<br>
        <b>Severity:</b> {incident.get("severity")}<br>
        <b>Threat Type:</b> {incident.get("threatType")}<br>
        <b>Brand:</b> {incident.get("brand")}<br>
        <b>Created:</b> {incident.get("createdUtc")}<br>

        <h4>URLs</h4>
        {"<br>".join(urls) if urls else "No URLs Found"}
    </div>
    """


# =========================================================
# BUILD ALERT
# =========================================================

def build_alert(siemplify, incident, seen_ids):

    incident_id = str(incident.get("incidentId"))

    # Deduplication
    if incident_id in seen_ids:
        return None

    seen_ids.add(incident_id)

    urls = [
        u.get("url")
        for u in incident.get("urlItems", [])
        if u.get("url")
    ]

    alert = AlertInfo()

    alert.display_id = incident_id
    alert.ticket_id = incident_id

    alert.name = "{} - {}".format(
        incident.get("incidentNumber", ""),
        incident.get("title", "")
    )

    alert.rule_generator = RULE_GENERATOR

    alert.device_vendor = VENDOR
    alert.device_product = PRODUCT

    alert.environment = siemplify.context.connector_info.environment

    alert.start_time = unix_now()
    alert.end_time = unix_now()

    severity_map = {
        "Critical": 100,
        "High": 80,
        "Medium": 60,
        "Low": 40
    }

    alert.priority = severity_map.get(
        incident.get("severity", "Medium"),
        60
    )

    html_widget = build_html_widget(incident, urls)

    # IMPORTANT:
    # ALL EVENT VALUES MUST BE STRINGS / PRIMITIVES
    event = {
        "StartTime": unix_now(),
        "EndTime": unix_now(),

        "IncidentID": str(incident.get("incidentId", "")),
        "IncidentNumber": str(incident.get("incidentNumber", "")),
        "Title": str(incident.get("title", "")),
        "Status": str(incident.get("status", "")),
        "Severity": str(incident.get("severity", "")),
        "ThreatType": str(incident.get("threatType", "")),
        "Brand": str(incident.get("brand", "")),

        # MUST BE STRING
        "URLs": "\n".join(urls),

        # MUST BE STRING
        "HTMLWidget": str(html_widget),

        # MUST BE STRING
        "RawJSON": json.dumps(incident)
    }

    alert.events.append(event)

    return alert


# =========================================================
# MAIN
# =========================================================

@output_handler
def main(is_test_run):

    alerts = []

    siemplify = SiemplifyConnectorExecution()
    siemplify.script_name = CONNECTOR_NAME

    if is_test_run:
        siemplify.LOGGER.info(
            '***** TEST RUN *****'
        )

    siemplify.LOGGER.info(
        '==================== Connector Started ===================='
    )

    # =====================================================
    # PARAMETERS
    # =====================================================

    client_id = siemplify.extract_connector_param(
        "Client ID",
        is_mandatory=True,
        print_value=False
    )

    client_secret = siemplify.extract_connector_param(
        "Client Secret",
        is_mandatory=True,
        print_value=False
    )

    page_number = siemplify.extract_connector_param(
        "Page Number",
        default_value=1,
        input_type=int,
        is_mandatory=False
    )

    page_size = siemplify.extract_connector_param(
        "Page Size",
        default_value=10,
        input_type=int,
        is_mandatory=False
    )

    statuses = siemplify.extract_connector_param(
        "Incident Statuses",
        default_value="RequiresInput,RequiresApproval",
        is_mandatory=False
    )

    severities = siemplify.extract_connector_param(
        "Severity Codes",
        default_value="High,Medium",
        is_mandatory=False
    )

    verify_ssl = siemplify.extract_connector_param(
        "Verify SSL",
        default_value=True,
        input_type=bool,
        is_mandatory=False
    )

    siemplify.LOGGER.info(
        f"Statuses: {statuses}"
    )

    siemplify.LOGGER.info(
        f"Severities: {severities}"
    )

    # =====================================================
    # AUTH
    # =====================================================

    siemplify.LOGGER.info("Generating bearer token")

    token = generate_bearer_token(
        client_id,
        client_secret,
        verify_ssl
    )

    siemplify.LOGGER.info("Bearer token generated successfully")

    # =====================================================
    # FETCH INCIDENTS
    # =====================================================

    siemplify.LOGGER.info("Fetching incidents")

    response = get_incidents(
        token,
        page_number,
        page_size,
        statuses,
        severities,
        verify_ssl
    )

    incidents = response.get("items", [])

    siemplify.LOGGER.info(
        f"Retrieved {len(incidents)} incidents"
    )

    # =====================================================
    # DEDUP MEMORY
    # =====================================================

    seen_ids = set()

    # =====================================================
    # BUILD ALERTS
    # =====================================================

    for incident in incidents:

        try:

            alert = build_alert(
                siemplify,
                incident,
                seen_ids
            )

            if alert:
                alerts.append(alert)

                siemplify.LOGGER.info(
                    f"Created alert for incident "
                    f"{incident.get('incidentId')}"
                )

        except Exception as e:

            siemplify.LOGGER.error(
                f"Failed processing incident "
                f"{incident.get('incidentId')}"
            )

            siemplify.LOGGER.exception(e)

    # =====================================================
    # FINISH
    # =====================================================

    siemplify.LOGGER.info(
        f"Created {len(alerts)} alerts"
    )

    siemplify.LOGGER.info(
        '==================== Connector Finished ===================='
    )

    siemplify.return_package(alerts)


if __name__ == "__main__":

    main(False)
