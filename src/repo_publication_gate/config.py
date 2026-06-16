from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import tomllib


VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}

DEFAULT_IGNORE_PATHS = [
    ".git/**",
    "**/.git/**",
    ".venv/**",
    "**/.venv/**",
    "venv/**",
    "**/venv/**",
    "node_modules/**",
    "**/node_modules/**",
    "build/**",
    "**/build/**",
    "dist/**",
    "**/dist/**",
    "__pycache__/**",
    "**/__pycache__/**",
    ".pytest_cache/**",
    "**/.pytest_cache/**",
    ".ruff_cache/**",
    "**/.ruff_cache/**",
]

DEFAULT_ALLOW_PATHS = [
    ".env.example",
    ".env.template",
]


@dataclass
class GateConfig:
    fail_on: str = "high"
    max_file_size_bytes: int = 5 * 1024 * 1024
    content_scan_max_bytes: int = 1024 * 1024
    ignore_paths: list[str] = field(default_factory=lambda: list(DEFAULT_IGNORE_PATHS))
    allow_paths: list[str] = field(default_factory=lambda: list(DEFAULT_ALLOW_PATHS))


def _require_positive_int(value: object, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def load_config(root: Path, explicit_path: Path | None = None) -> GateConfig:
    config_path = explicit_path or (root / ".repo-publication-gate.toml")
    config = GateConfig()

    if not config_path.exists():
        return config

    with config_path.open("rb") as handle:
        raw = tomllib.load(handle)

    gate = raw.get("gate", {})
    if not isinstance(gate, dict):
        raise ValueError("[gate] must be a TOML table")

    if "fail_on" in gate:
        fail_on = str(gate["fail_on"]).lower()
        if fail_on not in VALID_SEVERITIES:
            raise ValueError(f"fail_on must be one of: {', '.join(sorted(VALID_SEVERITIES))}")
        config.fail_on = fail_on

    if "max_file_size_bytes" in gate:
        config.max_file_size_bytes = _require_positive_int(
            gate["max_file_size_bytes"], "max_file_size_bytes"
        )

    if "content_scan_max_bytes" in gate:
        config.content_scan_max_bytes = _require_positive_int(
            gate["content_scan_max_bytes"], "content_scan_max_bytes"
        )

    if "ignore_paths" in gate:
        if not isinstance(gate["ignore_paths"], list) or not all(
            isinstance(item, str) for item in gate["ignore_paths"]
        ):
            raise ValueError("ignore_paths must be an array of strings")
        config.ignore_paths = list(gate["ignore_paths"])

    if "allow_paths" in gate:
        if not isinstance(gate["allow_paths"], list) or not all(
            isinstance(item, str) for item in gate["allow_paths"]
        ):
            raise ValueError("allow_paths must be an array of strings")
        config.allow_paths = list(gate["allow_paths"])

    return config


STARTER_CONFIG = """\
[gate]
fail_on = "high"
max_file_size_bytes = 5242880
content_scan_max_bytes = 1048576
ignore_paths = [
  ".git/**",
  ".venv/**",
  "venv/**",
  "node_modules/**",
  "build/**",
  "dist/**",
  "__pycache__/**",
]
allow_paths = [
  ".env.example",
  ".env.template",
]
"""
