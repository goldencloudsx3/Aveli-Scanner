"""
Configuration loader.

Reads aveli.yml (or env vars) to build a ScannerConfig.
"""

import os
from pathlib import Path
from typing import Optional

try:
    import yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False

from .detectors.secrets import Severity
from .scanner import ScannerConfig


_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def load_config(config_file: Optional[Path] = None) -> ScannerConfig:
    """Load ScannerConfig from YAML file and/or environment variables."""
    raw: dict = {}

    if config_file and config_file.exists() and _YAML_AVAILABLE:
        with open(config_file) as fh:
            raw = yaml.safe_load(fh) or {}

    def _get(key: str, default):
        """Check env var first, then YAML, then default."""
        env_key = f"AVELI_{key.upper()}"
        env_val = os.environ.get(env_key)
        if env_val is not None:
            return env_val
        return raw.get(key, default)

    workers = int(_get("workers", 20))
    timeout = int(_get("request_timeout", 12))
    rps = float(_get("requests_per_second", 20.0))
    min_sev_str = _get("min_severity", "high").lower()
    min_sev = _SEVERITY_MAP.get(min_sev_str, Severity.HIGH)

    # Build severity filter (all severities >= min_sev)
    levels = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    idx = levels.index(min_sev)
    severity_filter = set(levels[:idx + 1])

    return ScannerConfig(
        workers=workers,
        request_timeout=timeout,
        requests_per_second=rps,
        min_severity=min_sev,
        severity_filter=severity_filter,
        check_headers=bool(int(_get("check_headers", 1))),
        check_content=bool(int(_get("check_content", 1))),
        check_url_patterns=bool(int(_get("check_url_patterns", 1))),
        verify_ssl=bool(int(_get("verify_ssl", 0))),
    )
