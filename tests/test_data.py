from pathlib import Path

from veritas_ai.data import generate_dataset


def test_generation_is_deterministic(tmp_path: Path) -> None:
    first = generate_dataset(tmp_path / "first", count=60, seed=42)
    second = generate_dataset(tmp_path / "second", count=60, seed=42)
    assert first["files"] == second["files"]
    assert first["observation_count"] == 60
