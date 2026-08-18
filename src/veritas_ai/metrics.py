"""Labelled performance and distribution metrics."""

from __future__ import annotations

from itertools import pairwise
from typing import Any

import numpy as np
from sklearn.metrics import confusion_matrix, f1_score


def expected_calibration_error(
    probabilities: np.ndarray, labels: np.ndarray, bins: int = 10
) -> float:
    if len(labels) == 0:
        raise ValueError("Expected calibration error requires labels")
    confidence = probabilities.max(axis=1)
    predictions = probabilities.argmax(axis=1)
    edges = np.linspace(0.0, 1.0, bins + 1)
    result = 0.0
    for lower, upper in pairwise(edges):
        mask = (confidence > lower) & (confidence <= upper)
        if not np.any(mask):
            continue
        accuracy = float(np.mean(predictions[mask] == labels[mask]))
        result += float(np.mean(mask)) * abs(accuracy - float(np.mean(confidence[mask])))
    return result


def labelled_metrics(
    labels: np.ndarray, probabilities: np.ndarray, class_names: list[str]
) -> dict[str, Any]:
    if len(labels) == 0:
        raise ValueError("Labelled metrics require ground truth")
    predictions = probabilities.argmax(axis=1)
    matrix = confusion_matrix(labels, predictions, labels=list(range(len(class_names))))
    per_class: dict[str, dict[str, float]] = {}
    for index, name in enumerate(class_names):
        true_positive = float(matrix[index, index])
        false_negative = float(matrix[index, :].sum() - true_positive)
        false_positive = float(matrix[:, index].sum() - true_positive)
        true_negative = float(matrix.sum() - true_positive - false_negative - false_positive)
        per_class[name] = {
            "false_negative_rate": false_negative / max(true_positive + false_negative, 1.0),
            "false_positive_rate": false_positive / max(false_positive + true_negative, 1.0),
        }
    return {
        "sample_count": len(labels),
        "macro_f1": float(f1_score(labels, predictions, average="macro", zero_division=0)),
        "expected_calibration_error": expected_calibration_error(probabilities, labels),
        "confusion_matrix": matrix.tolist(),
        "per_class": per_class,
    }


def distribution_profile(values: np.ndarray, bins: int = 10) -> dict[str, list[float]]:
    finite = values[np.isfinite(values)]
    if len(finite) == 0:
        raise ValueError("Distribution profile requires finite values")
    thresholds = np.unique(np.quantile(finite, np.linspace(0.0, 1.0, bins + 1)[1:-1]))
    if len(thresholds) == 0:
        thresholds = np.array([float(finite[0])])
    histogram_edges = np.concatenate(([-np.inf], thresholds, [np.inf]))
    counts, _ = np.histogram(finite, bins=histogram_edges)
    proportions = (counts / max(counts.sum(), 1)).astype(float)
    return {"edges": thresholds.tolist(), "proportions": proportions.tolist()}


def population_stability_index(values: np.ndarray, profile: dict[str, list[float]]) -> float:
    thresholds = np.asarray(profile["edges"], dtype=float)
    edges = np.concatenate(([-np.inf], thresholds, [np.inf]))
    expected = np.asarray(profile["proportions"], dtype=float)
    finite = values[np.isfinite(values)]
    actual_counts, _ = np.histogram(finite, bins=edges)
    actual = actual_counts / max(actual_counts.sum(), 1)
    epsilon = 1e-6
    expected = np.clip(expected, epsilon, None)
    actual = np.clip(actual, epsilon, None)
    return float(np.sum((actual - expected) * np.log(actual / expected)))


def one_sided_cusum(
    values: np.ndarray, baseline_mean: float, baseline_std: float, allowance_sigma: float = 0.5
) -> float:
    scale = max(baseline_std, 1e-9)
    allowance = allowance_sigma * scale
    cumulative = 0.0
    maximum = 0.0
    for value in values:
        cumulative = max(0.0, cumulative + (float(value) - baseline_mean - allowance))
        maximum = max(maximum, cumulative)
    return maximum / scale
