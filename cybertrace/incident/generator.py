from datetime import timedelta

from cybertrace.event import AuthenticationEvent
from cybertrace.incident import SecurityIncident
from cybertrace.incident.correlation import find_successful_login
from cybertrace.incident.severity import calculate_severity


def generate_ssh_incidents(
    events: list[AuthenticationEvent],
    detections: list[AuthenticationEvent],
    window_minutes: int = 5,
) -> list[SecurityIncident]:
    """Convert SSH detections into enriched security incidents."""

    incidents = []

    failed_events = [
        event
        for event in events
        if event.event_type in {
            "ssh_failed_password",
            "ssh_invalid_user",
        }
        and not event.success
    ]

    for detection in detections:
        window_start = detection.timestamp - timedelta(
            minutes=window_minutes
        )

        matching_events = [
            event
            for event in failed_events
            if (
                event.source_ip == detection.source_ip
                and window_start <= event.timestamp <= detection.timestamp
            )
        ]

        if not matching_events:
            continue

        matching_events.sort(key=lambda event: event.timestamp)

        first_seen = matching_events[0].timestamp
        last_seen = matching_events[-1].timestamp

        duration_seconds = (
            last_seen - first_seen
        ).total_seconds()

        evidence = [
            event.raw_message
            for event in matching_events
        ]

        successful_login = find_successful_login(
            events=events,
            source_ip=detection.source_ip,
            username=detection.username,
            timestamp=detection.timestamp,
            window_minutes=window_minutes,
        )

        incident = SecurityIncident(
            incident_id=f"INC-{detection.event_id}",
            detection_type="ssh_bruteforce",
            severity="unknown",
            source_ip=detection.source_ip,
            username=detection.username,
            service=detection.service,
            first_seen=first_seen,
            last_seen=last_seen,
            attempt_count=len(matching_events),
            evidence=evidence,
            duration_seconds=duration_seconds,
            successful_login=successful_login is not None,
            successful_login_time=(
                successful_login.timestamp
                if successful_login is not None
                else None
            ),
        )

        incident.severity = calculate_severity(incident)

        incidents.append(incident)

    return incidents
