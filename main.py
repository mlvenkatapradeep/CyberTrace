from cybertrace.cli import create_parser
from cybertrace.collector.journal import collect_ssh_events
from cybertrace.parser.ssh import parse_ssh_record
from cybertrace.detection.ssh import detect_ssh_bruteforce
from cybertrace.incident.generator import generate_ssh_incidents
from cybertrace.reporting.report import (
    generate_report,
    save_json_report,
)
from cybertrace.config.loader import load_config


def main() -> None:
    """Run the complete CyberTrace detection and reporting pipeline."""

    parser = create_parser()
    args = parser.parse_args()

    print("=== CYBERTRACE PIPELINE ===")

    # 1. Load CyberTrace configuration
    config = load_config(args.config)

    ssh_config = config.get("ssh", {}).get("brute_force", {})

    threshold = ssh_config.get("threshold", 3)
    window_minutes = ssh_config.get("window_minutes", 5)

    json_config = config.get("reporting", {}).get("json", {})

    json_enabled = (
        json_config.get("enabled", True)
        and not args.no_json
    )

    json_output = json_config.get(
        "output",
        "reports/cybertrace_report.json",
    )

    # 2. Display active security configuration
    print()
    print("=== ACTIVE CONFIGURATION ===")
    print(f"SSH brute-force threshold : {threshold}")
    print(f"SSH detection window      : {window_minutes} minutes")
    print(f"Event collection limit    : {args.limit}")
    print(f"JSON reporting enabled    : {json_enabled}")
    print(f"JSON report output        : {json_output}")
    print()

    # 3. Collect raw SSH journal records
    records = collect_ssh_events(args.limit)

    # 4. Parse raw records into AuthenticationEvent objects
    events = [
        parse_ssh_record(record)
        for record in records
    ]

    events = [
        event
        for event in events
        if event is not None
    ]

    # 5. Detect SSH brute-force activity
    detections = detect_ssh_bruteforce(
        events,
        threshold=threshold,
        window_minutes=window_minutes,
    )

    # 6. Convert detections into SecurityIncident objects
    incidents = generate_ssh_incidents(
        events,
        detections,
        window_minutes=window_minutes,
    )

    print(f"Collected: {len(records)}")
    print(f"Parsed: {len(events)}")
    print(f"Detected: {len(detections)}")
    print(f"Incidents: {len(incidents)}")
    print()

    # 7. Generate human-readable report
    print(generate_report(incidents))

    # 8. Save machine-readable JSON report
    if json_enabled:
        save_json_report(
            incidents,
            json_output,
        )

        print()
        print("JSON report saved to:")
        print(json_output)


if __name__ == "__main__":
    main()
