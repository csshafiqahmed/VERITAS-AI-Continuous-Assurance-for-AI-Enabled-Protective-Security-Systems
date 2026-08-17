import json
from pathlib import Path

from typer.testing import CliRunner

from veritas_ai.cli import app
from veritas_ai.data import generate_dataset
from veritas_ai.io import read_json, read_jsonl, write_jsonl


def test_separate_command_workflows_preserve_label_boundary(tmp_path: Path) -> None:
    runner = CliRunner()
    data_dir = tmp_path / "data"
    model_dir = tmp_path / "model"
    baseline_path = tmp_path / "baseline.json"
    generate_dataset(data_dir, count=3750, seed=42)

    train_result = runner.invoke(
        app,
        [
            "train",
            "--telemetry",
            str(data_dir / "conn.log"),
            "--auth",
            str(data_dir / "auth.jsonl"),
            "--labels",
            str(data_dir / "labels.jsonl"),
            "--output",
            str(model_dir),
        ],
    )
    assert train_result.exit_code == 0, train_result.output
    assert json.loads(train_result.output)["feature_builder"]["observation_count"] == 3750

    baseline_result = runner.invoke(
        app,
        [
            "baseline",
            "--model",
            str(model_dir),
            "--dataset",
            str(model_dir / "training_observations.jsonl"),
            "--output",
            str(baseline_path),
        ],
    )
    assert baseline_result.exit_code == 0, baseline_result.output

    observations = read_jsonl(model_dir / "training_observations.jsonl")
    stable_records = [
        {name: value for name, value in record.items() if name != "label"}
        for record in observations
        if record["scenario"] == "stable_operation"
    ]
    stream_path = tmp_path / "stable.jsonl"
    write_jsonl(stream_path, stable_records)

    labelled_output = tmp_path / "labelled-monitor"
    labelled_result = runner.invoke(
        app,
        [
            "monitor",
            "--model",
            str(model_dir),
            "--baseline",
            str(baseline_path),
            "--stream",
            str(stream_path),
            "--labels",
            str(data_dir / "labels.jsonl"),
            "--output",
            str(labelled_output),
        ],
    )
    assert labelled_result.exit_code == 0, labelled_result.output
    labelled = read_json(labelled_output / "monitoring_result.json")
    assert labelled["labels_available"] is True
    assert labelled["labelled_metrics"] is not None

    unlabelled_output = tmp_path / "unlabelled-monitor"
    unlabelled_result = runner.invoke(
        app,
        [
            "monitor",
            "--model",
            str(model_dir),
            "--baseline",
            str(baseline_path),
            "--stream",
            str(stream_path),
            "--output",
            str(unlabelled_output),
        ],
    )
    assert unlabelled_result.exit_code == 0, unlabelled_result.output
    unlabelled = read_json(unlabelled_output / "monitoring_result.json")
    assert unlabelled["labels_available"] is False
    assert unlabelled["labelled_metrics"] is None
    assert unlabelled["ece_increase"] is None
    assert unlabelled["maximum_fnr_increase"] is None
