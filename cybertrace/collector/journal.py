import json
import subprocess


def collect_ssh_events(limit: int = 10) -> list[dict]:
    command = [
        "journalctl",
        "-u",
        "sshd",
        "-n",
        str(limit),
        "-o",
        "json",
        "--no-pager",
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=True,
    )

    records = []

    for line in result.stdout.splitlines():
        if line.strip():
            records.append(json.loads(line))

    return records
