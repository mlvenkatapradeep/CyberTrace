import json
import subprocess

import pytest

from cybertrace.collector.journal import (
    JournalCollectionError,
    collect_ssh_events,
)


def test_collect_ssh_events_parses_json_records(monkeypatch):
    stdout = "\n".join(
        [
            json.dumps(
                {
                    "MESSAGE": "first event",
                    "__REALTIME_TIMESTAMP": "1000000",
                }
            ),
            json.dumps(
                {
                    "MESSAGE": "second event",
                    "__REALTIME_TIMESTAMP": "2000000",
                }
            ),
        ]
    )

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args,
            returncode=0,
            stdout=stdout,
            stderr="",
        )

    monkeypatch.setattr(
        "cybertrace.collector.journal.subprocess.run",
        fake_run,
    )

    records = collect_ssh_events(limit=10)

    assert len(records) == 2
    assert records[0]["MESSAGE"] == "first event"
    assert records[1]["MESSAGE"] == "second event"


def test_collect_ssh_events_skips_blank_lines(monkeypatch):
    stdout = (
        "\n"
        '{"MESSAGE": "valid event"}\n'
        "\n"
        "   \n"
    )

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args,
            returncode=0,
            stdout=stdout,
            stderr="",
        )

    monkeypatch.setattr(
        "cybertrace.collector.journal.subprocess.run",
        fake_run,
    )

    records = collect_ssh_events()

    assert len(records) == 1
    assert records[0]["MESSAGE"] == "valid event"


def test_collect_ssh_events_skips_invalid_json(monkeypatch):
    stdout = "\n".join(
        [
            '{"MESSAGE": "valid event"}',
            "this is not valid json",
            '{"MESSAGE": "another valid event"}',
        ]
    )

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args,
            returncode=0,
            stdout=stdout,
            stderr="",
        )

    monkeypatch.setattr(
        "cybertrace.collector.journal.subprocess.run",
        fake_run,
    )

    records = collect_ssh_events()

    assert len(records) == 2
    assert records[0]["MESSAGE"] == "valid event"
    assert records[1]["MESSAGE"] == "another valid event"


def test_collect_ssh_events_skips_non_mapping_json(monkeypatch):
    stdout = "\n".join(
        [
            '{"MESSAGE": "valid event"}',
            '["not", "a", "mapping"]',
            '"just a string"',
            "42",
            '{"MESSAGE": "another valid event"}',
        ]
    )

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args,
            returncode=0,
            stdout=stdout,
            stderr="",
        )

    monkeypatch.setattr(
        "cybertrace.collector.journal.subprocess.run",
        fake_run,
    )

    records = collect_ssh_events()

    assert len(records) == 2
    assert records[0]["MESSAGE"] == "valid event"
    assert records[1]["MESSAGE"] == "another valid event"


def test_collect_ssh_events_raises_when_journalctl_missing(monkeypatch):
    def fake_run(*args, **kwargs):
        raise FileNotFoundError("journalctl not found")

    monkeypatch.setattr(
        "cybertrace.collector.journal.subprocess.run",
        fake_run,
    )

    with pytest.raises(
        JournalCollectionError,
        match="journalctl command was not found",
    ):
        collect_ssh_events()


def test_collect_ssh_events_raises_on_journalctl_failure(monkeypatch):
    def fake_run(*args, **kwargs):
        raise subprocess.CalledProcessError(
            returncode=1,
            cmd=args,
            stderr="permission denied",
        )

    monkeypatch.setattr(
        "cybertrace.collector.journal.subprocess.run",
        fake_run,
    )

    with pytest.raises(
        JournalCollectionError,
        match="journalctl failed: permission denied",
    ):
        collect_ssh_events()


def test_collect_ssh_events_reports_exit_code_without_stderr(monkeypatch):
    def fake_run(*args, **kwargs):
        raise subprocess.CalledProcessError(
            returncode=2,
            cmd=args,
            stderr="",
        )

    monkeypatch.setattr(
        "cybertrace.collector.journal.subprocess.run",
        fake_run,
    )

    with pytest.raises(
        JournalCollectionError,
        match="journalctl failed with exit code 2",
    ):
        collect_ssh_events()
