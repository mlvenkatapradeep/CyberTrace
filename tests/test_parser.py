from cybertrace.parser.ssh import parse_ssh_record


def test_parse_failed_ssh_password():
    record = {
        "MESSAGE": (
            "Failed password for invalid user testuser "
            "from 192.168.1.50 port 54321 ssh2"
        ),
        "__REALTIME_TIMESTAMP": "1757228400000000",
    }

    event = parse_ssh_record(record)

    assert event is not None
    assert event.event_type == "ssh_failed_password"
    assert event.username == "testuser"
    assert event.source_ip == "192.168.1.50"
    assert event.source_port == 54321
    assert event.service == "ssh"
    assert event.success is False


def test_parse_invalid_ssh_user():
    record = {
        "MESSAGE": (
            "Invalid user attacker "
            "from 10.0.0.25 port 44444"
        ),
        "__REALTIME_TIMESTAMP": "1757228400000000",
    }

    event = parse_ssh_record(record)

    assert event is not None
    assert event.event_type == "ssh_invalid_user"
    assert event.username == "attacker"
    assert event.source_ip == "10.0.0.25"
    assert event.source_port == 44444
    assert event.service == "ssh"
    assert event.success is False


def test_parse_successful_ssh_login():
    record = {
        "MESSAGE": (
            "Accepted password for budda "
            "from 192.168.1.100 port 55555 ssh2"
        ),
        "__REALTIME_TIMESTAMP": "1757228400000000",
    }

    event = parse_ssh_record(record)

    assert event is not None
    assert event.event_type == "ssh_success"
    assert event.username == "budda"
    assert event.source_ip == "192.168.1.100"
    assert event.source_port == 55555
    assert event.service == "ssh"
    assert event.success is True


def test_parse_empty_record():
    record = {}

    event = parse_ssh_record(record)

    assert event is None


def test_parse_unrecognized_message():
    record = {
        "MESSAGE": "Some unrelated system message",
        "__REALTIME_TIMESTAMP": "1757228400000000",
    }

    event = parse_ssh_record(record)

    assert event is None


def test_parse_missing_timestamp():
    record = {
        "MESSAGE": (
            "Invalid user attacker "
            "from 10.0.0.25 port 44444"
        ),
    }

    event = parse_ssh_record(record)

    assert event is None


def test_parse_invalid_timestamp():
    record = {
        "MESSAGE": (
            "Invalid user attacker "
            "from 10.0.0.25 port 44444"
        ),
        "__REALTIME_TIMESTAMP": "not-a-timestamp",
    }

    event = parse_ssh_record(record)

    assert event is None


def test_parse_invalid_timestamp_type():
    record = {
        "MESSAGE": (
            "Invalid user attacker "
            "from 10.0.0.25 port 44444"
        ),
        "__REALTIME_TIMESTAMP": object(),
    }

    event = parse_ssh_record(record)

    assert event is None
