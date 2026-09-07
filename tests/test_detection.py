from datetime import datetime, timedelta, timezone

from cybertrace.detection.ssh import detect_ssh_bruteforce
from cybertrace.event import AuthenticationEvent


def make_event(
    timestamp,
    event_type="ssh_failed_password",
    source_ip="192.168.1.50",
    username="testuser",
    success=False,
):
    return AuthenticationEvent(
        event_id=f"ssh-{timestamp.timestamp()}",
        timestamp=timestamp,
        event_type=event_type,
        username=username,
        source_ip=source_ip,
        source_port=54321,
        service="ssh",
        success=success,
        raw_message="test SSH authentication event",
    )


def test_detect_bruteforce_at_threshold():
    base_time = datetime(2026, 9, 7, 10, 0, tzinfo=timezone.utc)

    events = [
        make_event(base_time),
        make_event(base_time + timedelta(minutes=1)),
        make_event(base_time + timedelta(minutes=2)),
    ]

    detections = detect_ssh_bruteforce(
        events,
        threshold=3,
        window_minutes=5,
    )

    assert len(detections) == 1


def test_no_detection_below_threshold():
    base_time = datetime(2026, 9, 7, 10, 0, tzinfo=timezone.utc)

    events = [
        make_event(base_time),
        make_event(base_time + timedelta(minutes=1)),
    ]

    detections = detect_ssh_bruteforce(
        events,
        threshold=3,
        window_minutes=5,
    )

    assert len(detections) == 0


def test_no_detection_when_attempts_are_outside_window():
    base_time = datetime(2026, 9, 7, 10, 0, tzinfo=timezone.utc)

    events = [
        make_event(base_time),
        make_event(base_time + timedelta(minutes=6)),
        make_event(base_time + timedelta(minutes=12)),
    ]

    detections = detect_ssh_bruteforce(
        events,
        threshold=3,
        window_minutes=5,
    )

    assert len(detections) == 0


def test_different_source_ips_do_not_combine():
    base_time = datetime(2026, 9, 7, 10, 0, tzinfo=timezone.utc)

    events = [
        make_event(base_time, source_ip="192.168.1.10"),
        make_event(
            base_time + timedelta(minutes=1),
            source_ip="192.168.1.20",
        ),
        make_event(
            base_time + timedelta(minutes=2),
            source_ip="192.168.1.30",
        ),
    ]

    detections = detect_ssh_bruteforce(
        events,
        threshold=3,
        window_minutes=5,
    )

    assert len(detections) == 0


def test_successful_login_is_not_counted():
    base_time = datetime(2026, 9, 7, 10, 0, tzinfo=timezone.utc)

    events = [
        make_event(base_time),
        make_event(base_time + timedelta(minutes=1)),
        make_event(
            base_time + timedelta(minutes=2),
            event_type="ssh_success",
            success=True,
        ),
    ]

    detections = detect_ssh_bruteforce(
        events,
        threshold=3,
        window_minutes=5,
    )

    assert len(detections) == 0


def test_detection_at_exact_window_boundary():
    base_time = datetime(2026, 9, 7, 10, 0, tzinfo=timezone.utc)

    events = [
        make_event(base_time),
        make_event(base_time + timedelta(minutes=2)),
        make_event(base_time + timedelta(minutes=5)),
    ]

    detections = detect_ssh_bruteforce(
        events,
        threshold=3,
        window_minutes=5,
    )

    assert len(detections) == 1


def test_no_detection_just_outside_window_boundary():
    base_time = datetime(2026, 9, 7, 10, 0, tzinfo=timezone.utc)

    events = [
        make_event(base_time),
        make_event(base_time + timedelta(minutes=2)),
        make_event(base_time + timedelta(minutes=5, seconds=1)),
    ]

    detections = detect_ssh_bruteforce(
        events,
        threshold=3,
        window_minutes=5,
    )

    assert len(detections) == 0


def test_multiple_failures_from_same_ip():
    base_time = datetime(2026, 9, 7, 10, 0, tzinfo=timezone.utc)

    events = [
        make_event(base_time),
        make_event(base_time + timedelta(seconds=30)),
        make_event(base_time + timedelta(minutes=1)),
        make_event(base_time + timedelta(minutes=2)),
        make_event(base_time + timedelta(minutes=3)),
    ]

    detections = detect_ssh_bruteforce(
        events,
        threshold=3,
        window_minutes=5,
    )

    assert len(detections) == 1


def test_repeated_failures_within_window_create_one_detection():
    base_time = datetime(2026, 9, 7, 10, 0, tzinfo=timezone.utc)

    events = [
        make_event(base_time),
        make_event(base_time + timedelta(minutes=1)),
        make_event(base_time + timedelta(minutes=2)),
        make_event(base_time + timedelta(minutes=3)),
        make_event(base_time + timedelta(minutes=4)),
    ]

    detections = detect_ssh_bruteforce(
        events,
        threshold=3,
        window_minutes=5,
    )

    assert len(detections) == 1
    assert detections[0].timestamp == base_time + timedelta(minutes=2)
