from pathlib import Path

import yaml


DEFAULT_CONFIG_PATH = Path("config/cybertrace.yaml")


def load_config(config_path: str | Path = DEFAULT_CONFIG_PATH) -> dict:
    """Load and validate CyberTrace configuration from YAML."""

    path = Path(config_path)

    if not path.exists():
        raise FileNotFoundError(
            f"Configuration file not found: {path}"
        )

    with path.open("r", encoding="utf-8") as file:
        config = yaml.safe_load(file)

    if config is None:
        return {}

    if not isinstance(config, dict):
        raise ValueError(
            "CyberTrace configuration must contain a YAML mapping."
        )

    ssh_config = config.get("ssh", {})
    brute_force_config = ssh_config.get("brute_force", {})

    threshold = brute_force_config.get("threshold", 3)
    window_minutes = brute_force_config.get("window_minutes", 5)

    if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold < 1:
        raise ValueError(
            "SSH brute-force threshold must be a positive integer."
        )

    if not isinstance(window_minutes, int) or isinstance(window_minutes, bool) or window_minutes < 1:
        raise ValueError(
            "SSH brute-force window_minutes must be a positive integer."
        )

    return config
