import json
import subprocess
from pathlib import Path

import pytest
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


def test_dashboard_command_supports_guided_and_completed_modes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = CliRunner()
    calls: list[list[str]] = []

    def controlled(command: list[str], check: bool) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr("veritas_ai.cli.subprocess.run", controlled)
    guided = runner.invoke(
        app,
        ["dashboard", "--runs-root", str(tmp_path / "reviewer")],
    )
    assert guided.exit_code == 0, guided.output
    assert "--runs-root" in calls[-1]
    assert "--run" not in calls[-1]
    assert "127.0.0.1" in calls[-1]

    completed_run = tmp_path / "completed"
    completed_run.mkdir()
    evidence = runner.invoke(
        app,
        [
            "dashboard",
            "--run",
            str(completed_run),
            "--runs-root",
            str(tmp_path / "reviewer"),
            "--address",
            "0.0.0.0",
        ],
    )
    assert evidence.exit_code == 0, evidence.output
    assert calls[-1][-2:] == ["--run", str(completed_run.resolve())]
    assert "0.0.0.0" in calls[-1]


def test_dashboard_command_rejects_unbounded_address() -> None:
    result = CliRunner().invoke(app, ["dashboard", "--address", "192.0.2.10"])
    assert result.exit_code != 0
    assert "Address must be 127.0.0.1 or 0.0.0.0" in result.output
