from datetime import datetime, timedelta, timezone

from cybertrace.event import AuthenticationEvent
from cybertrace.incident import SecurityIncident
from cybertrace.incident.correlation import find_successful_login
from cybertrace.incident.generator import generate_ssh_incidents


def make_event(
    timestamp,
    event_id=None,
    event_type="ssh_failed_password",
    source_ip="192.168.1.50",
    username="testuser",
    success=False,
):
    if event_id is None:
        event_id = f"ssh-{timestamp.timestamp()}"

    return AuthenticationEvent(
        event_id=event_id,
        timestamp=timestamp,
        event_type=event_type,
        username=username,
        source_ip=source_ip,
        source_port=54321,
        service="ssh",
        success=success,
        raw_message="test SSH authentication event",
    )


def test_generate_ssh_incident():
    base_time = datetime(2026, 9, 7, 10, 0, tzinfo=timezone.utc)

    events = [
        make_event(base_time, event_id="ssh-1"),
        make_event(
            base_time + timedelta(minutes=1),
            event_id="ssh-2",
        ),
        make_event(
            base_time + timedelta(minutes=2),
            event_id="ssh-3",
        ),
    ]

    incidents = generate_ssh_incidents(
        events,
        [events[-1]],
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
    assert incident.successful_login is False
    assert incident.successful_login_time is None
    assert incident.severity == "low"


def test_successful_login_is_correlated():
    base_time = datetime(2026, 9, 7, 10, 0, tzinfo=timezone.utc)

    failed_events = [
        make_event(base_time, event_id="ssh-1"),
        make_event(
            base_time + timedelta(minutes=1),
            event_id="ssh-2",
        ),
        make_event(
            base_time + timedelta(minutes=2),
            event_id="ssh-3",
        ),
    ]

    successful_login = make_event(
        base_time + timedelta(minutes=3),
        event_id="ssh-success",
        event_type="ssh_success",
        success=True,
    )

    events = failed_events + [successful_login]

    incidents = generate_ssh_incidents(
        events,
        [failed_events[-1]],
        window_minutes=5,
    )

    assert len(incidents) == 1

    incident = incidents[0]

    assert incident.successful_login is True
    assert incident.successful_login_time == successful_login.timestamp
    assert incident.severity == "critical"


def test_no_incident_when_detection_has_no_matching_events():
    base_time = datetime(2026, 9, 7, 10, 0, tzinfo=timezone.utc)

    detection = make_event(
        base_time,
        event_id="ssh-detection",
        source_ip="10.0.0.99",
    )

    events = [
        make_event(
            base_time + timedelta(minutes=1),
            event_id="ssh-1",
            source_ip="10.0.0.50",
        )
    ]

    incidents = generate_ssh_incidents(
        events,
        [detection],
        window_minutes=5,
    )

    assert incidents == []


def test_successful_login_outside_window_is_not_correlated():
    base_time = datetime(2026, 9, 7, 10, 0, tzinfo=timezone.utc)

    failed_events = [
        make_event(base_time, event_id="ssh-1"),
        make_event(
            base_time + timedelta(minutes=1),
            event_id="ssh-2",
        ),
        make_event(
            base_time + timedelta(minutes=2),
            event_id="ssh-3",
        ),
    ]

    successful_login = make_event(
        base_time + timedelta(minutes=10),
        event_id="ssh-success",
        event_type="ssh_success",
        success=True,
    )

    events = failed_events + [successful_login]

    incidents = generate_ssh_incidents(
        events,
        [failed_events[-1]],
        window_minutes=5,
    )

    assert len(incidents) == 1
    assert incidents[0].successful_login is False
    assert incidents[0].successful_login_time is None
    assert incidents[0].severity == "low"


def test_different_source_ip_is_not_included():
    base_time = datetime(2026, 9, 7, 10, 0, tzinfo=timezone.utc)

    detection_events = [
        make_event(
            base_time,
            event_id="ssh-1",
            source_ip="192.168.1.50",
        ),
        make_event(
            base_time + timedelta(minutes=1),
            event_id="ssh-2",
            source_ip="192.168.1.50",
        ),
        make_event(
            base_time + timedelta(minutes=2),
            event_id="ssh-3",
            source_ip="192.168.1.50",
        ),
    ]

    unrelated_event = make_event(
        base_time + timedelta(minutes=2),
        event_id="ssh-other",
        source_ip="192.168.1.99",
    )

    events = detection_events + [unrelated_event]

    incidents = generate_ssh_incidents(
        events,
        [detection_events[-1]],
        window_minutes=5,
    )

    assert len(incidents) == 1
    assert incidents[0].attempt_count == 3
    assert incidents[0].source_ip == "192.168.1.50"


def test_incident_duration_is_calculated_correctly():
    base_time = datetime(2026, 9, 7, 10, 0, tzinfo=timezone.utc)

    events = [
        make_event(base_time, event_id="ssh-1"),
        make_event(
            base_time + timedelta(seconds=30),
            event_id="ssh-2",
        ),
        make_event(
            base_time + timedelta(minutes=2),
            event_id="ssh-3",
        ),
    ]

    incidents = generate_ssh_incidents(
        events,
        [events[-1]],
        window_minutes=5,
    )

    assert len(incidents) == 1
    assert incidents[0].duration_seconds == 120


def test_severity_is_low_for_three_to_five_attempts():
    base_time = datetime(2026, 9, 7, 10, 0, tzinfo=timezone.utc)

    events = [
        make_event(
            base_time + timedelta(seconds=index),
            event_id=f"ssh-{index}",
        )
        for index in range(3)
    ]

    incidents = generate_ssh_incidents(
        events,
        [events[-1]],
        window_minutes=5,
    )

    assert len(incidents) == 1
    assert incidents[0].attempt_count == 3
    assert incidents[0].severity == "low"


def test_severity_is_medium_for_six_to_nine_attempts():
    base_time = datetime(2026, 9, 7, 10, 0, tzinfo=timezone.utc)

    events = [
        make_event(
            base_time + timedelta(seconds=index),
            event_id=f"ssh-{index}",
        )
        for index in range(6)
    ]

    incidents = generate_ssh_incidents(
        events,
        [events[-1]],
        window_minutes=5,
    )

    assert len(incidents) == 1
    assert incidents[0].attempt_count == 6
    assert incidents[0].severity == "medium"


def test_severity_is_high_for_ten_or_more_attempts():
    base_time = datetime(2026, 9, 7, 10, 0, tzinfo=timezone.utc)

    events = [
        make_event(
            base_time + timedelta(seconds=index),
            event_id=f"ssh-{index}",
        )
        for index in range(10)
    ]

    incidents = generate_ssh_incidents(
        events,
        [events[-1]],
        window_minutes=5,
    )

    assert len(incidents) == 1
    assert incidents[0].attempt_count == 10
    assert incidents[0].severity == "high"


def test_successful_login_makes_incident_critical():
    base_time = datetime(2026, 9, 7, 10, 0, tzinfo=timezone.utc)

    failed_events = [
        make_event(
            base_time,
            event_id="ssh-1",
        ),
        make_event(
            base_time + timedelta(seconds=30),
            event_id="ssh-2",
        ),
        make_event(
            base_time + timedelta(minutes=1),
            event_id="ssh-3",
        ),
    ]

    successful_login = make_event(
        base_time + timedelta(minutes=2),
        event_id="ssh-success",
        event_type="ssh_success",
        success=True,
    )

    events = failed_events + [successful_login]

    incidents = generate_ssh_incidents(
        events,
        [failed_events[-1]],
        window_minutes=5,
    )

    assert len(incidents) == 1
    assert incidents[0].successful_login is True
    assert incidents[0].severity == "critical"


def test_find_successful_login_returns_matching_login():
    base_time = datetime(2026, 9, 7, 10, 0, tzinfo=timezone.utc)

    events = [
        make_event(base_time, event_id="ssh-1"),
        make_event(
            base_time + timedelta(minutes=1),
            event_id="ssh-2",
        ),
        make_event(
            base_time + timedelta(minutes=2),
            event_id="ssh-success",
            event_type="ssh_success",
            success=True,
        ),
    ]

    result = find_successful_login(
        events=events,
        source_ip="192.168.1.50",
        username="testuser",
        timestamp=base_time + timedelta(minutes=1),
        window_minutes=5,
    )

    assert result is not None
    assert result.event_id == "ssh-success"
