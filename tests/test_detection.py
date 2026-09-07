from datetime import datetime, timedelta, timezone

from cybertrace.detection.ssh import detect_ssh_bruteforce
from cybertrace.event import AuthenticationEvent


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
        make_event(base_time, event_id="ssh-1"),
        make_event(
            base_time + timedelta(seconds=30),
            event_id="ssh-2",
        ),
        make_event(
            base_time + timedelta(minutes=1),
            event_id="ssh-3",
        ),
        make_event(
            base_time + timedelta(minutes=2),
            event_id="ssh-4",
        ),
    ]

    detections = detect_ssh_bruteforce(
        events,
        threshold=3,
        window_minutes=5,
    )

    assert len(detections) == 1
    assert detections[0].event_id == "ssh-3"


def test_repeated_failures_within_window_create_one_detection():
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
        make_event(
            base_time + timedelta(minutes=3),
            event_id="ssh-4",
        ),
        make_event(
            base_time + timedelta(minutes=4),
            event_id="ssh-5",
        ),
    ]

    detections = detect_ssh_bruteforce(
        events,
        threshold=3,
        window_minutes=5,
    )

    assert len(detections) == 1
    assert detections[0].event_id == "ssh-3"


def test_separate_attack_sequences_after_cooldown_create_two_detections():
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
        make_event(
            base_time + timedelta(minutes=8),
            event_id="ssh-4",
        ),
        make_event(
            base_time + timedelta(minutes=9),
            event_id="ssh-5",
        ),
        make_event(
            base_time + timedelta(minutes=10),
            event_id="ssh-6",
        ),
    ]

    detections = detect_ssh_bruteforce(
        events,
        threshold=3,
        window_minutes=5,
    )

    assert len(detections) == 2
    assert detections[0].event_id == "ssh-3"
    assert detections[1].event_id == "ssh-6"


def test_different_usernames_from_same_ip_are_combined():
    base_time = datetime(2026, 9, 7, 10, 0, tzinfo=timezone.utc)

    events = [
        make_event(
            base_time,
            event_id="ssh-1",
            username="admin",
        ),
        make_event(
            base_time + timedelta(minutes=1),
            event_id="ssh-2",
            username="root",
        ),
        make_event(
            base_time + timedelta(minutes=2),
            event_id="ssh-3",
            username="testuser",
        ),
    ]

    detections = detect_ssh_bruteforce(
        events,
        threshold=3,
        window_minutes=5,
    )

    assert len(detections) == 1
    assert detections[0].event_id == "ssh-3"


def test_invalid_user_and_failed_password_are_combined():
    base_time = datetime(2026, 9, 7, 10, 0, tzinfo=timezone.utc)

    events = [
        make_event(
            base_time,
            event_id="ssh-1",
            event_type="ssh_invalid_user",
            username="attacker",
        ),
        make_event(
            base_time + timedelta(minutes=1),
            event_id="ssh-2",
            event_type="ssh_failed_password",
            username="attacker",
        ),
        make_event(
            base_time + timedelta(minutes=2),
            event_id="ssh-3",
            event_type="ssh_invalid_user",
            username="attacker",
        ),
    ]

    detections = detect_ssh_bruteforce(
        events,
        threshold=3,
        window_minutes=5,
    )

    assert len(detections) == 1
    assert detections[0].event_id == "ssh-3"


def test_events_out_of_order_are_detected_correctly():
    base_time = datetime(2026, 9, 7, 10, 0, tzinfo=timezone.utc)

    events = [
        make_event(
            base_time + timedelta(minutes=2),
            event_id="ssh-3",
        ),
        make_event(
            base_time,
            event_id="ssh-1",
        ),
        make_event(
            base_time + timedelta(minutes=1),
            event_id="ssh-2",
        ),
    ]

    detections = detect_ssh_bruteforce(
        events,
        threshold=3,
        window_minutes=5,
    )

    assert len(detections) == 1
    assert detections[0].event_id == "ssh-3"


def test_multiple_source_ips_create_independent_detections():
    base_time = datetime(2026, 9, 7, 10, 0, tzinfo=timezone.utc)

    events = [
        make_event(
            base_time,
            event_id="ip1-1",
            source_ip="192.168.1.10",
        ),
        make_event(
            base_time + timedelta(minutes=1),
            event_id="ip1-2",
            source_ip="192.168.1.10",
        ),
        make_event(
            base_time + timedelta(minutes=2),
            event_id="ip1-3",
            source_ip="192.168.1.10",
        ),
        make_event(
            base_time,
            event_id="ip2-1",
            source_ip="192.168.1.20",
        ),
        make_event(
            base_time + timedelta(minutes=1),
            event_id="ip2-2",
            source_ip="192.168.1.20",
        ),
        make_event(
            base_time + timedelta(minutes=2),
            event_id="ip2-3",
            source_ip="192.168.1.20",
        ),
    ]

    detections = detect_ssh_bruteforce(
        events,
        threshold=3,
        window_minutes=5,
    )

    assert len(detections) == 2

    detection_ids = {
        detection.event_id
        for detection in detections
    }

    assert detection_ids == {"ip1-3", "ip2-3"}


def test_long_attack_sequence_creates_only_one_detection():
    base_time = datetime(2026, 9, 7, 10, 0, tzinfo=timezone.utc)

    events = [
        make_event(
            base_time + timedelta(seconds=index * 30),
            event_id=f"ssh-{index}",
        )
        for index in range(10)
    ]

    detections = detect_ssh_bruteforce(
        events,
        threshold=3,
        window_minutes=5,
    )

    assert len(detections) == 1
    assert detections[0].event_id == "ssh-2"
