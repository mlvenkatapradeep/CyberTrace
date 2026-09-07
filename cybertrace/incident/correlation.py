from datetime import timedelta

from cybertrace.event import AuthenticationEvent


def find_successful_login(
    events: list[AuthenticationEvent],
    source_ip: str | None,
    username: str | None,
    timestamp,
    window_minutes: int = 5,
) -> AuthenticationEvent | None:
    """
    Find a successful SSH authentication following a detection.

    The successful authentication must:
    - be from the same source IP
    - target the same username when available
    - occur after the detection
    - occur within the configured time window
    """

    if source_ip is None:
        return None

    window_end = timestamp + timedelta(minutes=window_minutes)

    successful_events = [
        event
        for event in events
        if (
            event.event_type == "ssh_success"
            and event.success
            and event.source_ip == source_ip
            and event.timestamp >= timestamp
            and event.timestamp <= window_end
            and (
                username is None
                or event.username == username
            )
        )
    ]

    successful_events.sort(key=lambda event: event.timestamp)

    if not successful_events:
        return None

    return successful_events[0]
