import numpy as np
import pytest

from veritas_ai.metrics import (
    distribution_profile,
    expected_calibration_error,
    labelled_metrics,
    one_sided_cusum,
    population_stability_index,
)


def test_perfect_confident_predictions_have_zero_calibration_error() -> None:
    probabilities = np.array([[1.0, 0.0], [0.0, 1.0]])
    labels = np.array([0, 1])
    assert expected_calibration_error(probabilities, labels) == 0.0


def test_population_stability_index_is_near_zero_for_same_values() -> None:
    values = np.arange(100, dtype=float)
    profile = distribution_profile(values)
    assert population_stability_index(values, profile) < 1e-10


def test_labelled_metrics_reject_missing_ground_truth() -> None:
    with pytest.raises(ValueError, match="requires labels"):
        expected_calibration_error(np.empty((0, 2)), np.array([]))
    with pytest.raises(ValueError, match="require ground truth"):
        labelled_metrics(np.array([]), np.empty((0, 2)), ["a", "b"])


def test_distribution_profile_rejects_non_finite_values() -> None:
    with pytest.raises(ValueError, match="requires finite values"):
        distribution_profile(np.array([np.nan, np.inf]))


def test_single_bin_profile_and_cusum_are_finite() -> None:
    profile = distribution_profile(np.array([3.0, 3.0]), bins=1)
    assert profile["edges"] == [3.0]
    assert one_sided_cusum(np.array([0.0, 2.0]), 0.0, 1.0) == 1.5
