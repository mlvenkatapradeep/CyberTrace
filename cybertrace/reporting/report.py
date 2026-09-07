import json
from collections import Counter

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


def generate_summary(incidents: list[SecurityIncident]) -> dict:
    """Generate summary statistics for security incidents."""

    severity_counts = Counter(
        incident.severity
        for incident in incidents
    )

    unique_source_ips = {
        incident.source_ip
        for incident in incidents
    }

    successful_compromises = sum(
        1
        for incident in incidents
        if incident.successful_login
    )

    return {
        "total_incidents": len(incidents),
        "severity_counts": {
            "critical": severity_counts.get("critical", 0),
            "high": severity_counts.get("high", 0),
            "medium": severity_counts.get("medium", 0),
            "low": severity_counts.get("low", 0),
        },
        "successful_compromises": successful_compromises,
        "unique_source_ips": len(unique_source_ips),
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


def format_summary(incidents: list[SecurityIncident]) -> str:
    """Format incident summary statistics for human-readable output."""

    summary = generate_summary(incidents)
    severity_counts = summary["severity_counts"]

    return "\n".join(
        [
            "CYBERTRACE SECURITY SUMMARY",
            f"Total Incidents       : {summary['total_incidents']}",
            f"Critical Incidents    : {severity_counts['critical']}",
            f"High Incidents        : {severity_counts['high']}",
            f"Medium Incidents      : {severity_counts['medium']}",
            f"Low Incidents         : {severity_counts['low']}",
            f"Successful Compromise : {summary['successful_compromises']}",
            f"Unique Source IPs     : {summary['unique_source_ips']}",
        ]
    )


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
        format_summary(incidents),
        "",
    ]

    for incident in incidents:
        sections.append(format_incident(incident))

    return "\n".join(sections)


def generate_json_report(
    incidents: list[SecurityIncident],
) -> str:
    """Generate a JSON report containing summary and incident details."""

    summary = generate_summary(incidents)

    report = {
        "tool": "CyberTrace",
        "total_incidents": len(incidents),
        "summary": summary,
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
