# FortraBrandProtection
This is a Fortra Brand protection integration and few automations for Google SecOps

## Summary

This connector integrates Google SOAR with Fortra Brand Protection by authenticating to the Fortra API, retrieving brand protection incidents, and converting each incident into a SOAR alert.

The connector uses OAuth client credentials to generate a bearer token, queries the Fortra incident search API with configurable status, severity, page number, and page size parameters, and creates alerts for each returned incident. Each alert includes key incident metadata such as incident ID, incident number, title, status, severity, threat type, brand, affected URLs, and the raw incident JSON.

### Main Capabilities

- Authenticates to Fortra using Bearer tokens
- Retrieves Brand Protection incidents from the Fortra API
- Supports filtering by incident status and severity
- Converts Fortra incidents into Google SOAR alerts
- Maps Fortra severity values to SOAR alert priorities
- Stores incident details, URLs, raw JSON, and HTML widget content in event fields
- Supports SSL verification configuration
- Includes logging for authentication, retrieval, alert creation, and error handling

# Automations

1 - ApplyAction - Used to act on an existing Fortra Brand Protection incident. Common actions include:

- Mitigate (initiate takedown/remediation, monitoring, or whitelist)
- Add Comment
- Provide Input. The action requires the Incident ID and an Action Type Code, allowing analysts or SOAR playbooks to update the incident lifecycle and trigger mitigation activities.

2 - Alert Details - Retrieves the full details of a specific incident, including:

- Incident ID and status
- Threat type
- Severity
- Brand targeted
- URLs, domains, social media accounts, or other indicators
- Creation and modification timestamps
- Mitigation progress and current workflow status
- Notes and comments

3 - CreateIncident - Used to create a new DOMAIN incident in Fortra Brand Protection for investigation and tracking. The API allows submission of:
Incident Type (e.g., Social Media, Dark Web)

- Threat Type
- Brand information
- Threat indicators (URLs, accounts, domains, etc.)

