from pathlib import Path

import pytest

from veritas_ai.dashboard import dashboard_snapshot
from veritas_ai.io import read_json, write_json
from veritas_ai.ledger import sign_events


def _event(scenario: str, action: str) -> dict[str, object]:
    return {
        "scenario": scenario,
        "action": action,
        "maximum_psi": 0.05,
        "telemetry_missingness": 0.0,
        "labels_available": True,
        "reasons": ["inside_reference_envelope"],
    }


def test_dashboard_values_are_derived_from_signed_evidence(tmp_path: Path) -> None:
    events = [_event("stable_operation", "continue"), _event("model_replacement", "withdraw")]
    sign_events(events, tmp_path / "assurance_events.jsonl", tmp_path / "public_key.pem")
    write_json(
        tmp_path / "run_summary.json",
        {
            "version": "0.1.0",
            "ledger_valid": True,
            "scenario_actions": {
                "stable_operation": "continue",
                "model_replacement": "withdraw",
            },
        },
    )

    snapshot = dashboard_snapshot(tmp_path)
    assert snapshot["version"] == "0.1.0"
    assert snapshot["ledger_valid"] is True
    assert snapshot["scenario_count"] == 2
    assert (
        snapshot["scenario_actions"] == read_json(tmp_path / "run_summary.json")["scenario_actions"]
    )
    assert [row["action"] for row in snapshot["rows"]] == ["continue", "withdraw"]

    summary = read_json(tmp_path / "run_summary.json")
    summary["scenario_actions"]["stable_operation"] = "withdraw"
    write_json(tmp_path / "run_summary.json", summary)
    with pytest.raises(ValueError, match="do not match"):
        dashboard_snapshot(tmp_path)


def test_dashboard_rejects_tampered_ledger(tmp_path: Path) -> None:
    events = [_event("stable_operation", "continue")]
    sign_events(events, tmp_path / "assurance_events.jsonl", tmp_path / "public_key.pem")
    write_json(
        tmp_path / "run_summary.json",
        {
            "version": "0.1.0",
            "ledger_valid": True,
            "scenario_actions": {"stable_operation": "continue"},
        },
    )
    ledger = tmp_path / "assurance_events.jsonl"
    ledger.write_text(
        ledger.read_text(encoding="utf-8").replace("continue", "withdraw"), encoding="utf-8"
    )
    with pytest.raises(ValueError, match="invalid evidence ledger"):
        dashboard_snapshot(tmp_path)
