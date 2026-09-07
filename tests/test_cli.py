import pytest

from cybertrace.cli import create_parser


def test_cli_default_arguments():
    parser = create_parser()

    args = parser.parse_args([])

    assert args.config == "config/cybertrace.yaml"
    assert args.limit == 50
    assert args.no_json is False


def test_cli_custom_config():
    parser = create_parser()

    args = parser.parse_args(
        ["--config", "custom.yaml"]
    )

    assert args.config == "custom.yaml"


def test_cli_custom_limit():
    parser = create_parser()

    args = parser.parse_args(
        ["--limit", "100"]
    )

    assert args.limit == 100


def test_cli_no_json():
    parser = create_parser()

    args = parser.parse_args(
        ["--no-json"]
    )

    assert args.no_json is True


def test_cli_combined_arguments():
    parser = create_parser()

    args = parser.parse_args(
        [
            "--config",
            "test.yaml",
            "--limit",
            "25",
            "--no-json",
        ]
    )

    assert args.config == "test.yaml"
    assert args.limit == 25
    assert args.no_json is True


@pytest.mark.parametrize(
    "invalid_limit",
    ["0", "-1", "abc"],
)
def test_cli_rejects_invalid_limit(invalid_limit):
    parser = create_parser()

    with pytest.raises(SystemExit):
        parser.parse_args(
            ["--limit", invalid_limit]
        )
