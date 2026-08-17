import json
from pathlib import Path

from veritas_ai.ledger import verify_ledger
from veritas_ai.workflow import run_demo


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
