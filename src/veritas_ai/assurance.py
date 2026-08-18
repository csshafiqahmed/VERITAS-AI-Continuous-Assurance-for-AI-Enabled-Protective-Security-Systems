"""Reference baselining and continuous assurance decisions."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np

from veritas_ai.constants import CLASSES, FEATURES, SCHEMA_VERSION, THRESHOLDS
from veritas_ai.data import attach_ground_truth
from veritas_ai.io import canonical_json, read_json, read_jsonl, sha256_bytes, write_json
from veritas_ai.metrics import (
    distribution_profile,
    labelled_metrics,
    one_sided_cusum,
    population_stability_index,
)
from veritas_ai.model import encoded_labels, load_model, matrix, predict


def policy_hash() -> str:
    return sha256_bytes(canonical_json(THRESHOLDS))


def create_baseline(model_dir: Path, dataset_path: Path, output_path: Path) -> dict[str, Any]:
    records = [record for record in read_jsonl(dataset_path) if record.get("split") == "baseline"]
    if not records:
        raise ValueError("Dataset requires a non-empty baseline split")
    model, manifest = load_model(model_dir)
    probabilities, latency_ms = predict(model, records)
    labels = encoded_labels(records)
    values = matrix(records)
    profiles = {name: distribution_profile(values[:, index]) for index, name in enumerate(FEATURES)}
    confidence = probabilities.max(axis=1)
    baseline = {
        "schema_version": SCHEMA_VERSION,
        "created_at": datetime.now(UTC).isoformat(),
        "model_sha256": manifest["model_sha256"],
        "policy_sha256": policy_hash(),
        "features": FEATURES,
        "classes": CLASSES,
        "thresholds": THRESHOLDS,
        "labelled_metrics": labelled_metrics(labels, probabilities, CLASSES),
        "feature_profiles": profiles,
        "confidence": {
            "mean": float(np.mean(confidence)),
            "standard_deviation": float(np.std(confidence)),
            "profile": distribution_profile(confidence),
        },
        "inference_latency_ms": latency_ms,
        "telemetry_missingness": float(np.mean(values[:, FEATURES.index("telemetry_missing")])),
    }
    write_json(output_path, baseline)
    return baseline


def _maximum_fnr_increase(current: dict[str, Any], baseline: dict[str, Any]) -> float:
    increases = []
    for name in CLASSES:
        current_rate = current["per_class"][name]["false_negative_rate"]
        baseline_rate = baseline["per_class"][name]["false_negative_rate"]
        increases.append(float(current_rate) - float(baseline_rate))
    return max(increases, default=0.0)


def _advisory_decision(
    *,
    integrity_ok: bool,
    missingness: float,
    fnr_increase: float | None,
    ece_increase: float | None,
    labels_available: bool,
    context_approved: bool,
    max_psi: float,
    confidence_cusum: float,
) -> tuple[str, list[str]]:
    if not integrity_ok:
        return "withdraw", ["model_or_policy_integrity_mismatch"]
    if missingness >= THRESHOLDS["missing_critical"]:
        return "withdraw", ["critical_telemetry_missingness"]
    if fnr_increase is not None and fnr_increase >= THRESHOLDS["fnr_increase_critical"]:
        return "withdraw", ["critical_false_negative_deterioration"]
    if ece_increase is not None and ece_increase >= THRESHOLDS["ece_increase_critical"]:
        return "withdraw", ["critical_calibration_deterioration"]
    if (
        labels_available
        and not context_approved
        and (
            max_psi >= THRESHOLDS["psi_critical"]
            or (fnr_increase is not None and fnr_increase >= THRESHOLDS["fnr_increase_warning"])
            or (ece_increase is not None and ece_increase >= THRESHOLDS["ece_increase_warning"])
        )
    ):
        return "recalibrate", ["persistent_labelled_deterioration"]
    if missingness >= THRESHOLDS["missing_warning"]:
        return "investigate", ["partial_telemetry_loss"]
    if (
        not labels_available
        and not context_approved
        and confidence_cusum >= THRESHOLDS["cusum_decision_sigma"]
    ):
        return "investigate", ["confidence_cusum_threshold_exceeded"]
    if max_psi >= THRESHOLDS["psi_warning"] and not context_approved:
        return "investigate", ["feature_distribution_warning"]
    return "continue", []


def monitor_records(
    model_dir: Path,
    baseline_path: Path,
    records: list[dict[str, Any]],
    *,
    labels_available: bool = True,
    observed_model_hash: str | None = None,
    observed_policy_hash: str | None = None,
    context_approved: bool = False,
    operator_acknowledged: bool = False,
    stable_window_count: int = 0,
) -> dict[str, Any]:
    if not records:
        raise ValueError("Monitoring requires at least one observation")
    baseline = read_json(baseline_path)
    model, manifest = load_model(model_dir)
    probabilities, latency_ms = predict(model, records)
    values = matrix(records)
    psi = {
        name: population_stability_index(values[:, index], baseline["feature_profiles"][name])
        for index, name in enumerate(FEATURES)
    }
    confidence = probabilities.max(axis=1)
    confidence_cusum = one_sided_cusum(
        -confidence,
        -float(baseline["confidence"]["mean"]),
        float(baseline["confidence"]["standard_deviation"]),
        float(THRESHOLDS["cusum_allowance_sigma"]),
    )
    missingness = float(np.mean(values[:, FEATURES.index("telemetry_missing")]))
    labelled = (
        labelled_metrics(encoded_labels(records), probabilities, CLASSES)
        if labels_available
        else None
    )
    ece_increase = None
    fnr_increase = None
    if labelled is not None:
        ece_increase = float(labelled["expected_calibration_error"]) - float(
            baseline["labelled_metrics"]["expected_calibration_error"]
        )
        fnr_increase = _maximum_fnr_increase(labelled, baseline["labelled_metrics"])

    integrity = {
        "model_matches": (observed_model_hash or manifest["model_sha256"])
        == baseline["model_sha256"],
        "policy_matches": (observed_policy_hash or policy_hash()) == baseline["policy_sha256"],
    }
    max_psi = max(psi.values())
    action, reasons = _advisory_decision(
        integrity_ok=all(integrity.values()),
        missingness=missingness,
        fnr_increase=fnr_increase,
        ece_increase=ece_increase,
        labels_available=labels_available,
        context_approved=context_approved,
        max_psi=max_psi,
        confidence_cusum=confidence_cusum,
    )

    if operator_acknowledged and stable_window_count >= 2 and action == "continue":
        reasons.append("acknowledged_recovery_with_two_stable_windows")
    elif context_approved and action == "continue":
        reasons.append("approved_context_change")
    elif not reasons:
        reasons.append("inside_reference_envelope")

    return {
        "schema_version": SCHEMA_VERSION,
        "observed_at": datetime.now(UTC).isoformat(),
        "sample_count": len(records),
        "labels_available": labels_available,
        "scenario": str(records[0].get("scenario", "unspecified")),
        "action": action,
        "reasons": reasons,
        "integrity": integrity,
        "maximum_psi": max_psi,
        "feature_psi": psi,
        "telemetry_missingness": missingness,
        "confidence_cusum_sigma": confidence_cusum,
        "inference_latency_ms": latency_ms,
        "labelled_metrics": labelled,
        "ece_increase": ece_increase,
        "maximum_fnr_increase": fnr_increase,
    }


def monitor_dataset(
    model_dir: Path,
    baseline_path: Path,
    stream_path: Path,
    output_dir: Path,
    labels_path: Path | None = None,
) -> dict[str, Any]:
    records = read_jsonl(stream_path)
    if labels_path is not None:
        records = attach_ground_truth(records, labels_path)
    result = monitor_records(
        model_dir,
        baseline_path,
        records,
        labels_available=labels_path is not None,
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    write_json(output_dir / "monitoring_result.json", result)
    return result
