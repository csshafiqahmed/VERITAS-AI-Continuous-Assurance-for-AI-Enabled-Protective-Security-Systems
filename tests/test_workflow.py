import json
import subprocess
from pathlib import Path

import pytest

from veritas_ai.io import read_jsonl
from veritas_ai.ledger import verify_ledger
from veritas_ai.workflow import (
    _evaluate_recovery,
    _git_revision,
    _ProgressEmitter,
    complete_guided_demo,
    prepare_guided_demo,
    read_guided_state,
    run_demo,
)


def test_complete_demo_produces_verifiable_evidence(tmp_path: Path) -> None:
    progress = []
    run_dir = tmp_path / "run"
    summary = run_demo(run_dir, observer=progress.append)
    assert summary["ledger_valid"] is True
    assert summary["limitations"][-1] == "not_trl_6"
    assert set(summary["scenario_actions"]) == {
        "stable_operation",
        "benign_workload_change",
        "partial_telemetry_loss",
        "gradual_feature_drift",
        "model_replacement",
        "recovery_after_investigation",
    }
    assert summary["scenario_actions"] == {
        "stable_operation": "continue",
        "benign_workload_change": "continue",
        "partial_telemetry_loss": "investigate",
        "gradual_feature_drift": "recalibrate",
        "model_replacement": "withdraw",
        "recovery_after_investigation": "continue",
    }
    assert verify_ledger(tmp_path / "run/assurance_events.jsonl", tmp_path / "run/public_key.pem")[
        "valid"
    ]
    report = json.loads((tmp_path / "run/verification_report.json").read_text())
    assert report["events_checked"] == 6
    assert report["ledger_schema_version"] == "1.1.0"
    assert summary["version"] == "0.2.0"
    assert summary["demonstration"] == {
        "mode": "automatic_cli",
        "telemetry_source": "synthetic_zeek_compatible",
        "zeek_validated": False,
        "operator_acknowledged": True,
        "recovery_window_count": 2,
    }

    signed_events = [
        record["event"]
        for record in read_jsonl(run_dir / "assurance_events.jsonl")
        if record["record_type"] == "event"
    ]
    partial_loss = next(
        event for event in signed_events if event["scenario"] == "partial_telemetry_loss"
    )
    assert partial_loss["labels_available"] is False
    assert partial_loss["labelled_metrics"] is None
    assert partial_loss["ece_increase"] is None
    assert partial_loss["maximum_fnr_increase"] is None
    recovery = signed_events[-1]
    assert recovery["operator_acknowledged"] is True
    assert recovery["stable_window_count"] == 2
    assert [check["sample_count"] for check in recovery["recovery_checks"]] == [125, 125]
    assert all(check["action"] == "continue" for check in recovery["recovery_checks"])
    assert all(check["within_warning_envelope"] for check in recovery["recovery_checks"])

    assert [event.sequence for event in progress] == list(range(1, len(progress) + 1))
    assert [event.elapsed_seconds for event in progress] == sorted(
        event.elapsed_seconds for event in progress
    )
    generation_counts = {
        event.current
        for event in progress
        if event.stage == "telemetry_generation" and event.current is not None
    }
    assert set(range(0, 5001, 250)).issubset(generation_counts)
    for event in progress:
        if event.current is not None and event.total is not None:
            assert 0 <= event.current <= event.total
        if event.artifact is not None and event.state == "completed":
            assert (run_dir / event.artifact).is_file()
    assert read_guided_state(run_dir)["phase"] == "completed"


def test_guided_demo_requires_acknowledgement_before_signing(tmp_path: Path) -> None:
    run_dir = tmp_path / "guided"
    prepared = prepare_guided_demo(run_dir)

    assert prepared["state"]["phase"] == "awaiting_acknowledgement"
    assert not (run_dir / "assurance_events.jsonl").exists()
    assert not (run_dir / "run_summary.json").exists()
    with pytest.raises(PermissionError, match="acknowledgement is required"):
        complete_guided_demo(run_dir, operator_acknowledged=False)

    summary = complete_guided_demo(run_dir, operator_acknowledged=True)
    assert summary["demonstration"]["mode"] == "guided_reviewer"
    assert summary["ledger_valid"] is True
    assert read_guided_state(run_dir)["phase"] == "completed"


def test_failed_recovery_window_prevents_continue(monkeypatch: pytest.MonkeyPatch) -> None:
    actions = iter(["continue", "investigate", "continue"])

    def controlled_monitor(*args: object, **kwargs: object) -> dict[str, object]:
        action = next(actions)
        return {
            "scenario": "recovery_after_investigation",
            "action": action,
            "reasons": ["inside_reference_envelope"],
            "sample_count": 125,
            "labels_available": True,
            "maximum_psi": 0.05 if action == "continue" else 0.15,
            "telemetry_missingness": 0.0,
            "integrity": {"model_matches": True, "policy_matches": True},
        }

    monkeypatch.setattr("veritas_ai.workflow.monitor_records", controlled_monitor)
    records = [
        {"scenario": "recovery_after_investigation", "window_id": f"w{index:03d}"}
        for index in range(250)
    ]
    result = _evaluate_recovery(Path("model"), Path("baseline"), records, _ProgressEmitter(None))

    assert result["action"] == "investigate"
    assert result["stable_window_count"] == 1
    assert result["reasons"] == ["recovery_requirements_not_met"]


def test_git_revision_is_optional(monkeypatch: pytest.MonkeyPatch) -> None:
    def unavailable(*args: object, **kwargs: object) -> None:
        raise FileNotFoundError

    monkeypatch.setattr("veritas_ai.workflow.subprocess.run", unavailable)
    assert _git_revision() == "unavailable"


def test_git_revision_is_bound_to_project_checkout(monkeypatch: pytest.MonkeyPatch) -> None:
    project_root = Path(__file__).resolve().parents[1]
    revision = "a" * 40
    calls: list[list[str]] = []

    def controlled(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        output = f"{project_root}\n" if "--show-toplevel" in command else f"{revision}\n"
        return subprocess.CompletedProcess(command, 0, stdout=output, stderr="")

    monkeypatch.setattr("veritas_ai.workflow.subprocess.run", controlled)
    assert _git_revision() == revision
    assert len(calls) == 2
    assert all(command[:3] == ["git", "-C", str(project_root)] for command in calls)
