import json

from cybertrace.incident import SecurityIncident


def incident_to_dict(incident: SecurityIncident) -> dict:
    """Convert a SecurityIncident into a JSON-compatible dictionary."""

    return {
        "incident_id": incident.incident_id,
        "detection_type": incident.detection_type,
        "severity": incident.severity,
        "source_ip": incident.source_ip,
        "username": incident.username,
        "service": incident.service,
        "first_seen": incident.first_seen.isoformat(),
        "last_seen": incident.last_seen.isoformat(),
        "duration_seconds": incident.duration_seconds,
        "attempt_count": incident.attempt_count,
        "successful_login": incident.successful_login,
        "successful_login_time": (
            incident.successful_login_time.isoformat()
            if incident.successful_login_time is not None
            else None
        ),
        "evidence": incident.evidence,
    }


def format_incident(incident: SecurityIncident) -> str:
    """Format a SecurityIncident as a readable security report."""

    lines = [
        "=" * 60,
        "CYBERTRACE SECURITY INCIDENT",
        "=" * 60,
        f"Incident ID      : {incident.incident_id}",
        f"Detection Type   : {incident.detection_type}",
        f"Severity         : {incident.severity}",
        f"Source IP        : {incident.source_ip}",
        f"Username         : {incident.username}",
        f"Service          : {incident.service}",
        f"First Seen       : {incident.first_seen}",
        f"Last Seen        : {incident.last_seen}",
        f"Duration         : {incident.duration_seconds:.2f} seconds",
        f"Attempts         : {incident.attempt_count}",
        f"Successful Login : {incident.successful_login}",
        f"Success Time     : {incident.successful_login_time}",
        "",
        "Evidence:",
    ]

    for number, evidence in enumerate(incident.evidence, start=1):
        lines.append(f"  [{number}] {evidence}")

    lines.append("=" * 60)

    return "\n".join(lines)


def generate_report(incidents: list[SecurityIncident]) -> str:
    """Generate a complete human-readable report."""

    if not incidents:
        return (
            "CYBERTRACE SECURITY REPORT\n\n"
            "No security incidents detected."
        )

    sections = [
        "CYBERTRACE SECURITY REPORT",
        f"Total Incidents: {len(incidents)}",
        "",
    ]

    for incident in incidents:
        sections.append(format_incident(incident))

    return "\n".join(sections)


def generate_json_report(
    incidents: list[SecurityIncident],
) -> str:
    """Generate a JSON report containing multiple incidents."""

    report = {
        "tool": "CyberTrace",
        "total_incidents": len(incidents),
        "incidents": [
            incident_to_dict(incident)
            for incident in incidents
        ],
    }

    return json.dumps(report, indent=2)


def save_json_report(
    incidents: list[SecurityIncident],
    output_path: str,
) -> None:
    """Generate a JSON report and save it to a file."""

    report = generate_json_report(incidents)

    with open(output_path, "w", encoding="utf-8") as file:
        file.write(report)
