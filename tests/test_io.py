import math

import pytest

from veritas_ai.io import canonical_json, read_json, read_jsonl, write_json, write_jsonl


def test_canonical_json_is_stable() -> None:
    assert canonical_json({"b": 2, "a": 1}) == b'{"a":1,"b":2}'


def test_canonical_json_rejects_non_finite_numbers() -> None:
    with pytest.raises(ValueError):
        canonical_json({"value": math.nan})


def test_json_round_trip_and_object_validation(tmp_path) -> None:
    document = tmp_path / "nested/document.json"
    write_json(document, {"value": 1})
    assert read_json(document) == {"value": 1}
    document.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="Expected a JSON object"):
        read_json(document)


def test_jsonl_round_trip_skips_blanks_and_rejects_arrays(tmp_path) -> None:
    document = tmp_path / "records.jsonl"
    write_jsonl(document, [{"value": 1}, {"value": 2}])
    document.write_text(document.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    assert read_jsonl(document) == [{"value": 1}, {"value": 2}]
    document.write_text("[]\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Expected an object"):
        read_jsonl(document)
