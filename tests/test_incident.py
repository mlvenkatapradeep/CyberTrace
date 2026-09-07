from datetime import datetime, timedelta, timezone

from cybertrace.event import AuthenticationEvent
from cybertrace.incident.generator import generate_ssh_incidents


def make_event(
    timestamp,
    event_id,
    event_type="ssh_failed_password",
    source_ip="192.168.1.50",
    username="testuser",
    success=False,
    raw_message="test SSH event",
):
    return AuthenticationEvent(
        event_id=event_id,
        timestamp=timestamp,
        event_type=event_type,
        username=username,
        source_ip=source_ip,
        source_port=54321,
        service="ssh",
        success=success,
        raw_message=raw_message,
    )


def test_generate_ssh_incident():
    base_time = datetime(2026, 9, 7, 10, 0, tzinfo=timezone.utc)

    events = [
        make_event(
            base_time,
            "ssh-1",
            raw_message="Invalid user testuser from 192.168.1.50 port 54321",
        ),
        make_event(
            base_time + timedelta(minutes=1),
            "ssh-2",
            raw_message="Failed password for invalid user testuser from 192.168.1.50 port 54321 ssh2",
        ),
        make_event(
            base_time + timedelta(minutes=2),
            "ssh-3",
            raw_message="Failed password for invalid user testuser from 192.168.1.50 port 54321 ssh2",
        ),
    ]

    detections = [events[2]]

    incidents = generate_ssh_incidents(
        events,
        detections,
        window_minutes=5,
    )

    assert len(incidents) == 1

    incident = incidents[0]

    assert incident.incident_id == "INC-ssh-3"
    assert incident.detection_type == "ssh_bruteforce"
    assert incident.source_ip == "192.168.1.50"
    assert incident.username == "testuser"
    assert incident.service == "ssh"
    assert incident.attempt_count == 3
    assert incident.first_seen == base_time
    assert incident.last_seen == base_time + timedelta(minutes=2)
    assert incident.duration_seconds == 120.0
    assert len(incident.evidence) == 3


def test_successful_login_is_correlated():
    base_time = datetime(2026, 9, 7, 10, 0, tzinfo=timezone.utc)

    failed_events = [
        make_event(base_time, "ssh-1"),
        make_event(
            base_time + timedelta(minutes=1),
            "ssh-2",
        ),
        make_event(
            base_time + timedelta(minutes=2),
            "ssh-3",
        ),
    ]

    successful_event = make_event(
        base_time + timedelta(minutes=3),
        "ssh-success",
        event_type="ssh_success",
        success=True,
        raw_message="Accepted password for testuser from 192.168.1.50 port 54321 ssh2",
    )

    events = failed_events + [successful_event]

    incidents = generate_ssh_incidents(
        events,
        [failed_events[2]],
        window_minutes=5,
    )

    assert len(incidents) == 1

    incident = incidents[0]

    assert incident.successful_login is True
    assert incident.successful_login_time == successful_event.timestamp


def test_no_incident_when_detection_has_no_matching_events():
    base_time = datetime(2026, 9, 7, 10, 0, tzinfo=timezone.utc)

    detection = make_event(
        base_time,
        "ssh-detection",
        source_ip="10.0.0.99",
    )

    unrelated_event = make_event(
        base_time,
        "ssh-unrelated",
        source_ip="192.168.1.50",
    )

    incidents = generate_ssh_incidents(
        [unrelated_event],
        [detection],
        window_minutes=5,
    )

    assert len(incidents) == 0


def test_successful_login_outside_window_is_not_correlated():
    base_time = datetime(2026, 9, 7, 10, 0, tzinfo=timezone.utc)

    failed_events = [
        make_event(base_time, "ssh-1"),
        make_event(
            base_time + timedelta(minutes=1),
            "ssh-2",
        ),
        make_event(
            base_time + timedelta(minutes=2),
            "ssh-3",
        ),
    ]

    successful_event = make_event(
        base_time + timedelta(minutes=8),
        "ssh-success",
        event_type="ssh_success",
        success=True,
        raw_message="Accepted password for testuser from 192.168.1.50 port 54321 ssh2",
    )

    events = failed_events + [successful_event]

    incidents = generate_ssh_incidents(
        events,
        [failed_events[2]],
        window_minutes=5,
    )

    assert len(incidents) == 1

    incident = incidents[0]

    assert incident.successful_login is False
    assert incident.successful_login_time is None


def test_different_source_ip_is_not_included():
    base_time = datetime(2026, 9, 7, 10, 0, tzinfo=timezone.utc)

    matching_events = [
        make_event(base_time, "ssh-1"),
        make_event(
            base_time + timedelta(minutes=1),
            "ssh-2",
        ),
        make_event(
            base_time + timedelta(minutes=2),
            "ssh-3",
        ),
    ]

    unrelated_event = make_event(
        base_time + timedelta(minutes=1),
        "ssh-other",
        source_ip="10.0.0.99",
        raw_message="Failed password from unrelated source",
    )

    events = matching_events + [unrelated_event]

    incidents = generate_ssh_incidents(
        events,
        [matching_events[2]],
        window_minutes=5,
    )

    assert len(incidents) == 1

    incident = incidents[0]

    assert incident.attempt_count == 3
    assert len(incident.evidence) == 3
    assert all(
        "unrelated source" not in evidence
        for evidence in incident.evidence
    )


def test_incident_duration_is_calculated_correctly():
    base_time = datetime(2026, 9, 7, 10, 0, tzinfo=timezone.utc)

    events = [
        make_event(base_time, "ssh-1"),
        make_event(
            base_time + timedelta(seconds=30),
            "ssh-2",
        ),
        make_event(
            base_time + timedelta(seconds=90),
            "ssh-3",
        ),
    ]

    incidents = generate_ssh_incidents(
        events,
        [events[2]],
        window_minutes=5,
    )

    assert len(incidents) == 1
    assert incidents[0].duration_seconds == 90.0
