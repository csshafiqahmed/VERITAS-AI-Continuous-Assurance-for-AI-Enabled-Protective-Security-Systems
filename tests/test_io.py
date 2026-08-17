import math

import pytest

from veritas_ai.io import canonical_json


def test_canonical_json_is_stable() -> None:
    assert canonical_json({"b": 2, "a": 1}) == b'{"a":1,"b":2}'


def test_canonical_json_rejects_non_finite_numbers() -> None:
    with pytest.raises(ValueError):
        canonical_json({"value": math.nan})
