from cybertrace.incident import SecurityIncident


def calculate_severity(incident: SecurityIncident) -> str:
    """
    Calculate incident severity from the available incident context.

    Rules:
    - Successful login after brute-force activity: critical
    - 10 or more attempts: high
    - 6 to 9 attempts: medium
    - 3 to 5 attempts: low
    """

    if incident.successful_login:
        return "critical"

    if incident.attempt_count >= 10:
        return "high"

    if incident.attempt_count >= 6:
        return "medium"

    return "low"
