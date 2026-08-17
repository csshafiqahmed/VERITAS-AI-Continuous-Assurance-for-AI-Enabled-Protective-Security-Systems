import numpy as np

from veritas_ai.metrics import (
    distribution_profile,
    expected_calibration_error,
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
