import pytest
import yaml

from cybertrace.config.loader import load_config


def write_config(tmp_path, content):
    config_path = tmp_path / "cybertrace.yaml"
    config_path.write_text(content, encoding="utf-8")
    return config_path


def test_load_valid_configuration(tmp_path):
    config_path = write_config(
        tmp_path,
        """
ssh:
  brute_force:
    threshold: 3
    window_minutes: 5

reporting:
  json:
    enabled: true
    output: reports/cybertrace_report.json
""",
    )

    config = load_config(config_path)

    assert config["ssh"]["brute_force"]["threshold"] == 3
    assert config["ssh"]["brute_force"]["window_minutes"] == 5
    assert config["reporting"]["json"]["enabled"] is True


def test_missing_configuration_file():
    with pytest.raises(FileNotFoundError):
        load_config("does-not-exist.yaml")


def test_configuration_must_be_mapping(tmp_path):
    config_path = write_config(
        tmp_path,
        """
- item1
- item2
""",
    )

    with pytest.raises(ValueError, match="must contain a YAML mapping"):
        load_config(config_path)


@pytest.mark.parametrize("threshold", [0, -1, "three", True])
def test_invalid_threshold_is_rejected(tmp_path, threshold):
    config_path = tmp_path / "cybertrace.yaml"

    config_path.write_text(
        yaml.safe_dump(
            {
                "ssh": {
                    "brute_force": {
                        "threshold": threshold,
                        "window_minutes": 5,
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="threshold must be a positive integer",
    ):
        load_config(config_path)


@pytest.mark.parametrize("window_minutes", [0, -1, "five", True])
def test_invalid_window_is_rejected(tmp_path, window_minutes):
    config_path = tmp_path / "cybertrace.yaml"

    config_path.write_text(
        yaml.safe_dump(
            {
                "ssh": {
                    "brute_force": {
                        "threshold": 3,
                        "window_minutes": window_minutes,
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="window_minutes must be a positive integer",
    ):
        load_config(config_path)
