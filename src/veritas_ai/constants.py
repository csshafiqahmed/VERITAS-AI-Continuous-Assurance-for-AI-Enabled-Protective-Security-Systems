"""Shared feature, class, and policy definitions."""

from typing import Final

SCHEMA_VERSION: Final = "1.0"
DEFAULT_SEED: Final = 42

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
