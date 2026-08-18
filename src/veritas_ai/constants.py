"""Shared feature, class, and policy definitions."""

from typing import Final

SCHEMA_VERSION: Final = "1.1.0"
LEGACY_SCHEMA_VERSIONS: Final = frozenset({"1.0"})
SUPPORTED_SCHEMA_VERSIONS: Final = frozenset({SCHEMA_VERSION, *LEGACY_SCHEMA_VERSIONS})
DEFAULT_SEED: Final = 42
ZEEK_VERSION: Final = "8.0.9"
ZEEK_IMAGE: Final = (
    "zeek/zeek:8.0.9@sha256:b705c8932220e5e9e7af3e6519c8b41188aa190066e456f16ab6cfb7d97b760d"
)

CLASSES: Final = [
    "benign",
    "authentication_abuse",
    "reconnaissance",
    "lateral_movement",
    "abnormal_data_transfer",
]

FEATURES: Final = [
    "duration",
    "orig_bytes",
    "resp_bytes",
    "orig_pkts",
    "resp_pkts",
    "unique_destinations",
    "failed_auth",
    "new_service_ratio",
    "connection_rate",
    "telemetry_missing",
]

THRESHOLDS: Final = {
    "psi_warning": 0.10,
    "psi_critical": 0.25,
    "missing_warning": 0.05,
    "missing_critical": 0.20,
    "ece_increase_warning": 0.03,
    "ece_increase_critical": 0.08,
    "fnr_increase_warning": 0.05,
    "fnr_increase_critical": 0.10,
    "cusum_allowance_sigma": 0.5,
    "cusum_decision_sigma": 5.0,
}
