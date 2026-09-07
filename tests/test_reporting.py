import json
from datetime import datetime, timezone

from cybertrace.incident import SecurityIncident
from cybertrace.reporting.report import (
    format_incident,
    generate_json_report,
    generate_report,
    incident_to_dict,
    save_json_report,
)


def make_incident():
    timestamp = datetime(
        2026,
        9,
        7,
        10,
        0,
        tzinfo=timezone.utc,
    )

    return SecurityIncident(
        incident_id="INC-test-001",
        detection_type="ssh_bruteforce",
        severity="low",
        source_ip="192.168.1.50",
        username="testuser",
        service="ssh",
        first_seen=timestamp,
        last_seen=timestamp,
        attempt_count=3,
        evidence=[
            "Invalid user testuser from 192.168.1.50 port 54321",
            "Failed password for invalid user testuser from 192.168.1.50 port 54321 ssh2",
        ],
        duration_seconds=0.0,
        successful_login=False,
        successful_login_time=None,
    )


def test_incident_to_dict():
    incident = make_incident()

    result = incident_to_dict(incident)

    assert result["incident_id"] == "INC-test-001"
    assert result["detection_type"] == "ssh_bruteforce"
    assert result["severity"] == "low"
    assert result["source_ip"] == "192.168.1.50"
    assert result["username"] == "testuser"
    assert result["service"] == "ssh"
    assert result["attempt_count"] == 3
    assert result["successful_login"] is False
    assert result["successful_login_time"] is None
    assert len(result["evidence"]) == 2


def test_format_incident_contains_key_information():
    incident = make_incident()

    report = format_incident(incident)

    assert "CYBERTRACE SECURITY INCIDENT" in report
    assert "INC-test-001" in report
    assert "ssh_bruteforce" in report
    assert "192.168.1.50" in report
    assert "testuser" in report
    assert "Attempts         : 3" in report
    assert "Evidence:" in report


def test_generate_report_with_incident():
    incident = make_incident()

    report = generate_report([incident])

    assert "CYBERTRACE SECURITY REPORT" in report
    assert "Total Incidents: 1" in report
    assert "INC-test-001" in report


def test_generate_report_with_no_incidents():
    report = generate_report([])

    assert report == (
        "CYBERTRACE SECURITY REPORT\n\n"
        "No security incidents detected."
    )


def test_generate_json_report_is_valid_json():
    incident = make_incident()

    report = generate_json_report([incident])

    data = json.loads(report)

    assert data["tool"] == "CyberTrace"
    assert data["total_incidents"] == 1
    assert len(data["incidents"]) == 1
    assert data["incidents"][0]["incident_id"] == "INC-test-001"


def test_generate_json_report_preserves_timestamps():
    incident = make_incident()

    report = generate_json_report([incident])

    data = json.loads(report)
    exported = data["incidents"][0]

    assert exported["first_seen"] == "2026-09-07T10:00:00+00:00"
    assert exported["last_seen"] == "2026-09-07T10:00:00+00:00"


def test_save_json_report(tmp_path):
    incident = make_incident()
    output_path = tmp_path / "cybertrace_report.json"

    save_json_report(
        [incident],
        str(output_path),
    )

    assert output_path.exists()

    data = json.loads(
        output_path.read_text(encoding="utf-8")
    )

    assert data["tool"] == "CyberTrace"
    assert data["total_incidents"] == 1
    assert data["incidents"][0]["incident_id"] == "INC-test-001"
