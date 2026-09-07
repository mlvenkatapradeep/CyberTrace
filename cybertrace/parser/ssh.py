import re
from datetime import datetime, timezone

from cybertrace.event import AuthenticationEvent


def parse_ssh_record(record: dict) -> AuthenticationEvent | None:
    """Parse one raw journald SSH record into an AuthenticationEvent."""
    message = record.get("MESSAGE", "")

    if not message:
        return None

    failed_password_pattern = re.compile(
        r"Failed password for invalid user (?P<username>\S+) "
        r"from (?P<source_ip>\S+) port (?P<source_port>\d+) ssh2"
    )

    invalid_user_pattern = re.compile(
        r"Invalid user (?P<username>\S+) "
        r"from (?P<source_ip>\S+) port (?P<source_port>\d+)"
    )

    accepted_password_pattern = re.compile(
        r"Accepted password for (?P<username>\S+) "
        r"from (?P<source_ip>\S+) port (?P<source_port>\d+) ssh2"
    )

    match = failed_password_pattern.search(message)
    event_type = None
    success = False

    if match:
        event_type = "ssh_failed_password"
    else:
        match = invalid_user_pattern.search(message)

        if match:
            event_type = "ssh_invalid_user"
        else:
            match = accepted_password_pattern.search(message)

            if match:
                event_type = "ssh_success"
                success = True

    if not match:
        return None

    username = match.group("username")
    source_ip = match.group("source_ip")
    source_port = int(match.group("source_port"))

    timestamp_us = record.get("__REALTIME_TIMESTAMP")

    if not timestamp_us:
        return None

    try:
        timestamp = datetime.fromtimestamp(
            int(timestamp_us) / 1_000_000,
            tz=timezone.utc,
        )
    except (TypeError, ValueError, OverflowError):
        return None

    return AuthenticationEvent(
        event_id=f"ssh-{timestamp_us}",
        timestamp=timestamp,
        event_type=event_type,
        username=username,
        source_ip=source_ip,
        source_port=source_port,
        service="ssh",
        success=success,
        raw_message=message,
    )
