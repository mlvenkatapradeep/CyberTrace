from datetime import timedelta

from cybertrace.event import AuthenticationEvent


def detect_ssh_bruteforce(
    events: list[AuthenticationEvent],
    threshold: int = 3,
    window_minutes: int = 5,
) -> list[AuthenticationEvent]:
    """
    Detect repeated failed SSH authentication attempts.

    Returns the first event that completes a threshold-sized
    failure sequence from the same source IP within the
    configured time window.
    """

    failed_events = sorted(
        [
            event
            for event in events
            if event.event_type in {
                "ssh_failed_password",
                "ssh_invalid_user",
            }
            and not event.success
        ],
        key=lambda event: event.timestamp,
    )

    detections = []
    last_detection_by_ip = {}

    for current_event in failed_events:
        window_start = current_event.timestamp - timedelta(
            minutes=window_minutes
        )

        matching_events = [
            event
            for event in failed_events
            if (
                event.source_ip == current_event.source_ip
                and window_start <= event.timestamp <= current_event.timestamp
            )
        ]

        if len(matching_events) >= threshold:
            last_detection = last_detection_by_ip.get(
                current_event.source_ip
            )

            if (
                last_detection is None
                or current_event.timestamp - last_detection
                > timedelta(minutes=window_minutes)
            ):
                detections.append(current_event)
                last_detection_by_ip[current_event.source_ip] = (
                    current_event.timestamp
                )

    return detections
