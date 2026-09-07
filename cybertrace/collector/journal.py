import json
import subprocess


class JournalCollectionError(RuntimeError):
    """Raised when SSH journal collection fails."""


def collect_ssh_events(limit: int = 10) -> list[dict]:
    """Collect SSH journal records as JSON dictionaries."""

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

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
        )
    except FileNotFoundError as exc:
        raise JournalCollectionError(
            "journalctl command was not found."
        ) from exc
    except subprocess.CalledProcessError as exc:
        error = exc.stderr.strip()

        if error:
            message = f"journalctl failed: {error}"
        else:
            message = (
                f"journalctl failed with exit code {exc.returncode}."
            )

        raise JournalCollectionError(message) from exc

    records = []

    for line in result.stdout.splitlines():
        if not line.strip():
            continue

        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue

        if isinstance(record, dict):
            records.append(record)

    return records
