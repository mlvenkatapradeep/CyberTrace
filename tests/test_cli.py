import json

from main import run_pipeline


def test_run_pipeline_end_to_end(tmp_path, monkeypatch, capsys):
    config_path = tmp_path / "cybertrace.yaml"
    config_path.write_text(
        """
ssh:
  brute_force:
    threshold: 3
    window_minutes: 5

reporting:
  json:
    enabled: true
    output: reports/test_report.json
""",
        encoding="utf-8",
    )

    records = [
        {
            "timestamp": "2026-09-07T10:00:00+00:00",
            "message": (
                "Invalid user testuser from 192.168.1.50 "
                "port 54321"
            ),
        },
        {
            "timestamp": "2026-09-07T10:01:00+00:00",
            "message": (
                "Failed password for invalid user testuser "
                "from 192.168.1.50 port 54321 ssh2"
            ),
        },
        {
            "timestamp": "2026-09-07T10:02:00+00:00",
            "message": (
                "Failed password for invalid user testuser "
                "from 192.168.1.50 port 54321 ssh2"
            ),
        },
    ]

    monkeypatch.setattr(
        "main.collect_ssh_events",
        lambda limit: records,
    )

    monkeypatch.chdir(tmp_path)

    incidents = run_pipeline(
        config_path=str(config_path),
        limit=50,
    )

    captured = capsys.readouterr()

    assert len(incidents) == 1
    assert incidents[0].detection_type == "ssh_bruteforce"
    assert incidents[0].severity == "low"
    assert incidents[0].source_ip == "192.168.1.50"
    assert incidents[0].attempt_count == 3

    assert "Collected: 3" in captured.out
    assert "Parsed: 3" in captured.out
    assert "Detected: 1" in captured.out
    assert "Incidents: 1" in captured.out

    report_path = tmp_path / "reports" / "test_report.json"

    assert report_path.exists()

    data = json.loads(
        report_path.read_text(encoding="utf-8")
    )

    assert data["tool"] == "CyberTrace"
    assert data["total_incidents"] == 1
    assert data["summary"]["total_incidents"] == 1
    assert data["incidents"][0]["incident_id"].startswith("INC-")


def test_run_pipeline_no_json(tmp_path, monkeypatch, capsys):
    config_path = tmp_path / "cybertrace.yaml"
    config_path.write_text(
        """
ssh:
  brute_force:
    threshold: 3
    window_minutes: 5

reporting:
  json:
    enabled: true
    output: reports/test_report.json
""",
        encoding="utf-8",
    )

    records = [
        {
            "timestamp": "2026-09-07T10:00:00+00:00",
            "message": (
                "Invalid user testuser from 192.168.1.50 "
                "port 54321"
            ),
        },
        {
            "timestamp": "2026-09-07T10:01:00+00:00",
            "message": (
                "Failed password for invalid user testuser "
                "from 192.168.1.50 port 54321 ssh2"
            ),
        },
        {
            "timestamp": "2026-09-07T10:02:00+00:00",
            "message": (
                "Failed password for invalid user testuser "
                "from 192.168.1.50 port 54321 ssh2"
            ),
        },
    ]

    monkeypatch.setattr(
        "main.collect_ssh_events",
        lambda limit: records,
    )

    monkeypatch.chdir(tmp_path)

    incidents = run_pipeline(
        config_path=str(config_path),
        limit=50,
        no_json=True,
    )

    captured = capsys.readouterr()

    assert len(incidents) == 1
    assert incidents[0].severity == "low"

    assert "JSON reporting enabled    : False" in captured.out
    assert "JSON report saved to:" not in captured.out

    report_path = tmp_path / "reports" / "test_report.json"

    assert not report_path.exists()
