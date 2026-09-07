import argparse


def positive_integer(value: str) -> int:
    """Validate that a command-line value is a positive integer."""

    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "must be an integer"
        ) from exc

    if number < 1:
        raise argparse.ArgumentTypeError(
            "must be a positive integer"
        )

    return number


def create_parser() -> argparse.ArgumentParser:
    """Create the CyberTrace command-line argument parser."""

    parser = argparse.ArgumentParser(
        prog="cybertrace",
        description="CyberTrace SSH security monitoring and detection tool.",
    )

    parser.add_argument(
        "--config",
        default="config/cybertrace.yaml",
        help="Path to the CyberTrace YAML configuration file.",
    )

    parser.add_argument(
        "--limit",
        type=positive_integer,
        default=50,
        help="Maximum number of SSH journal records to collect.",
    )

    parser.add_argument(
        "--no-json",
        action="store_true",
        help="Disable JSON report generation for this run.",
    )

    return parser
