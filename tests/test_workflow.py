import json
import subprocess
from pathlib import Path

import pytest

from veritas_ai.ledger import verify_ledger
from veritas_ai.workflow import _git_revision, run_demo


def test_complete_demo_produces_verifiable_evidence(tmp_path: Path) -> None:
    summary = run_demo(tmp_path / "run")
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
