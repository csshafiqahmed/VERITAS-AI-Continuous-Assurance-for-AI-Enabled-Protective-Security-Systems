from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from veritas_ai.dashboard import ActiveRunRegistry, dashboard_snapshot
from veritas_ai.io import read_json, sha256_file, write_json
from veritas_ai.ledger import sign_events, write_verification_report


def _event(scenario: str, action: str) -> dict[str, object]:
    return {
        "scenario": scenario,
        "action": action,
        "maximum_psi": 0.05,
        "telemetry_missingness": 0.0,
        "labels_available": True,
        "reasons": ["inside_reference_envelope"],
    }


def _write_completed_run(tmp_path: Path, events: list[dict[str, object]]) -> None:
    data_dir = tmp_path / "data"
    model_dir = tmp_path / "model"
    data_dir.mkdir()
    model_dir.mkdir()
    (data_dir / "observations.jsonl").write_text("{}\n", encoding="utf-8")
    (model_dir / "model.json").write_text("{}\n", encoding="utf-8")
    dataset_manifest = {
        "schema_version": "1.0",
        "zeek_mode": "synthetic_zeek_compatible",
        "files": {"observations.jsonl": sha256_file(data_dir / "observations.jsonl")},
    }
    model_manifest = {
        "schema_version": "1.0",
        "model_sha256": sha256_file(model_dir / "model.json"),
        "classes": [],
    }
    write_json(data_dir / "dataset_manifest.json", dataset_manifest)
    write_json(model_dir / "model_manifest.json", model_manifest)
    write_json(
        tmp_path / "baseline.json",
        {
            "schema_version": "1.0",
            "model_sha256": model_manifest["model_sha256"],
            "policy_sha256": "b" * 64,
        },
    )
    sign_events(
        events,
        tmp_path / "assurance_events.jsonl",
        tmp_path / "public_key.pem",
        schema_version="1.0",
    )
    write_verification_report(
        tmp_path / "assurance_events.jsonl",
        tmp_path / "public_key.pem",
        tmp_path / "verification_report.json",
    )
    write_json(
        tmp_path / "run_summary.json",
        {
            "schema_version": "1.0",
            "version": "0.1.0",
            "trl_claim": "Evidence consistent with TRL 3 laboratory proof of concept",
            "limitations": ["not_trl_6"],
            "dataset_manifest": dataset_manifest,
            "model_manifest": model_manifest,
            "ledger_valid": True,
            "scenario_actions": {str(event["scenario"]): str(event["action"]) for event in events},
            "artifacts": {
                name: sha256_file(tmp_path / name)
                for name in (
                    "baseline.json",
                    "assurance_events.jsonl",
                    "public_key.pem",
                    "verification_report.json",
                )
            },
        },
    )


def test_active_run_registry_rejects_a_different_checkpoint(tmp_path: Path) -> None:
    registry = ActiveRunRegistry()
    first = tmp_path / "first"
    second = tmp_path / "second"

    assert registry.claim(first) is True
    assert registry.claim(first) is True
    assert registry.claim(second) is False
    registry.release(first)
    assert registry.claim(second) is True


def test_dashboard_values_are_derived_from_signed_evidence(tmp_path: Path) -> None:
    events = [_event("stable_operation", "continue"), _event("model_replacement", "withdraw")]
    _write_completed_run(tmp_path, events)

    snapshot = dashboard_snapshot(tmp_path)
    assert snapshot["version"] == "0.1.0"
    assert snapshot["ledger_valid"] is True
    assert snapshot["scenario_count"] == 2
    assert (
        snapshot["scenario_actions"] == read_json(tmp_path / "run_summary.json")["scenario_actions"]
    )
    assert [row["action"] for row in snapshot["rows"]] == ["continue", "withdraw"]
    assert snapshot["rows"][0]["reason"] == "Inside the reference envelope"

    summary = read_json(tmp_path / "run_summary.json")
    summary["scenario_actions"]["stable_operation"] = "withdraw"
    write_json(tmp_path / "run_summary.json", summary)
    with pytest.raises(ValueError, match="do not match"):
        dashboard_snapshot(tmp_path)


def test_dashboard_rejects_tampered_ledger(tmp_path: Path) -> None:
    events = [_event("stable_operation", "continue")]
    _write_completed_run(tmp_path, events)
    ledger = tmp_path / "assurance_events.jsonl"
    ledger.write_text(
        ledger.read_text(encoding="utf-8").replace("continue", "withdraw"), encoding="utf-8"
    )
    with pytest.raises(ValueError, match="invalid evidence ledger"):
        dashboard_snapshot(tmp_path)


def test_streamlit_opens_guided_mode_without_existing_run(tmp_path: Path) -> None:
    dashboard_file = Path(__file__).parents[1] / "src" / "veritas_ai" / "dashboard.py"
    app = AppTest.from_file(str(dashboard_file), default_timeout=15)
    app.args = ["--runs-root", str(tmp_path / "reviewer")]

    app.run(timeout=15)

    assert not app.exception
    assert app.title[0].value == "VERITAS-AI Guided Reviewer Demonstration"
    assert any(button.label == "Start New Demonstration" for button in app.button)


def test_streamlit_opens_verified_evidence_mode(tmp_path: Path) -> None:
    _write_completed_run(tmp_path, [_event("stable_operation", "continue")])
    script = f"""
from pathlib import Path
from veritas_ai.dashboard import DashboardConfig, render_application
reviewer_root = Path({str(tmp_path / "reviewer")!r})
completed_run = Path({str(tmp_path)!r})
render_application(DashboardConfig(runs_root=reviewer_root, run=completed_run))
"""
    app = AppTest.from_string(script, default_timeout=15)

    app.run(timeout=15)

    assert not app.exception
    assert app.title[0].value == "VERITAS-AI Signed Evidence Review"
    assert any(metric.label == "Ledger" and metric.value == "Valid" for metric in app.metric)


def test_streamlit_guided_controls_reach_signed_evidence(tmp_path: Path) -> None:
    script = f"""
from pathlib import Path
import veritas_ai.dashboard as dashboard
from veritas_ai.io import sha256_file, write_json
from veritas_ai.ledger import sign_events, write_verification_report
from veritas_ai.workflow import ProgressEvent

def fake_prepare(run_dir, regenerate_zeek=False, observer=None):
    if observer is not None:
        observer(ProgressEvent(1, "preflight", "completed", "Run workspace is ready", 0.01))
    actions = {{
        "stable_operation": "continue",
        "benign_workload_change": "continue",
        "partial_telemetry_loss": "investigate",
        "gradual_feature_drift": "recalibrate",
        "model_replacement": "withdraw",
    }}
    state = {{
        "internal_format": 1,
        "phase": "awaiting_acknowledgement",
        "mode": "guided_reviewer",
        "regenerate_zeek": regenerate_zeek,
        "seed": 42,
        "started_at": "2026-08-18T04:00:00+00:00",
        "updated_at": "2026-08-18T04:00:01+00:00",
        "progress_sequence": 1,
        "elapsed_seconds": 0.01,
        "provisional_actions": actions,
        "error": None,
    }}
    write_json(run_dir / ".guided-state.json", state)
    return {{"provisional_events": [], "state": state}}

def fake_complete(run_dir, operator_acknowledged, observer=None):
    scenarios = [
        ("stable_operation", "continue"),
        ("benign_workload_change", "continue"),
        ("partial_telemetry_loss", "investigate"),
        ("gradual_feature_drift", "recalibrate"),
        ("model_replacement", "withdraw"),
        ("recovery_after_investigation", "continue"),
    ]
    events = []
    for scenario, action in scenarios:
        event = {{
            "scenario": scenario,
            "action": action,
            "reasons": ["inside_reference_envelope"],
            "sample_count": 250,
            "labels_available": scenario != "partial_telemetry_loss",
            "maximum_psi": 0.02,
            "feature_psi": {{}},
            "telemetry_missingness": 0.0,
            "confidence_cusum_sigma": 0.0,
            "inference_latency_ms": 1.0,
            "integrity": {{"model_matches": True, "policy_matches": True}},
        }}
        if scenario == "recovery_after_investigation":
            event["operator_acknowledged"] = True
            event["stable_window_count"] = 2
            event["recovery_checks"] = []
        events.append(event)
    data_dir = run_dir / "data"
    model_dir = run_dir / "model"
    data_dir.mkdir()
    model_dir.mkdir()
    (data_dir / "observations.jsonl").write_bytes(b"{{}}")
    (model_dir / "model.json").write_bytes(b"{{}}")
    dataset_manifest = {{
        "schema_version": "1.0",
        "zeek_mode": "synthetic_zeek_compatible",
        "files": {{"observations.jsonl": sha256_file(data_dir / "observations.jsonl")}},
    }}
    model_manifest = {{
        "schema_version": "1.0",
        "model_sha256": sha256_file(model_dir / "model.json"),
        "classes": [],
    }}
    write_json(data_dir / "dataset_manifest.json", dataset_manifest)
    write_json(model_dir / "model_manifest.json", model_manifest)
    write_json(
        run_dir / "baseline.json",
        {{
            "schema_version": "1.0",
            "model_sha256": model_manifest["model_sha256"],
            "policy_sha256": "b" * 64,
        }},
    )
    sign_events(
        events,
        run_dir / "assurance_events.jsonl",
        run_dir / "public_key.pem",
        schema_version="1.0",
    )
    report = write_verification_report(
        run_dir / "assurance_events.jsonl",
        run_dir / "public_key.pem",
        run_dir / "verification_report.json",
    )
    summary = {{
        "schema_version": "1.0",
        "version": "0.1.0",
        "seed": 42,
        "git_revision": "test",
        "trl_claim": "Evidence consistent with TRL 3 laboratory proof of concept",
        "limitations": ["not_trl_6"],
        "demonstration": {{
            "mode": "guided_reviewer",
            "telemetry_source": "synthetic_zeek_compatible",
            "zeek_validated": False,
            "operator_acknowledged": True,
            "recovery_window_count": 2,
        }},
        "dataset_manifest": dataset_manifest,
        "model_manifest": model_manifest,
        "scenario_actions": {{scenario: action for scenario, action in scenarios}},
        "ledger_valid": report["valid"],
        "artifacts": {{
            name: sha256_file(run_dir / name)
            for name in (
                "baseline.json",
                "assurance_events.jsonl",
                "public_key.pem",
                "verification_report.json",
            )
        }},
    }}
    write_json(run_dir / "run_summary.json", summary)
    state = {{
        "internal_format": 1,
        "phase": "completed",
        "mode": "guided_reviewer",
        "regenerate_zeek": False,
        "seed": 42,
        "started_at": "2026-08-18T04:00:00+00:00",
        "updated_at": "2026-08-18T04:00:02+00:00",
        "progress_sequence": 2,
        "elapsed_seconds": 0.02,
        "provisional_actions": summary["scenario_actions"],
        "error": None,
    }}
    write_json(run_dir / ".guided-state.json", state)
    if observer is not None:
        observer(
            ProgressEvent(
                2,
                "evidence_preparation",
                "completed",
                "Verified reviewer evidence is ready",
                0.02,
            )
        )
    return summary

dashboard.prepare_guided_demo = fake_prepare
dashboard.complete_guided_demo = fake_complete
dashboard.render_application(
    dashboard.DashboardConfig(runs_root=Path({str(tmp_path / "reviewer")!r}))
)
"""
    app = AppTest.from_string(script, default_timeout=15)
    app.run(timeout=15)

    next(button for button in app.button if button.label == "Start New Demonstration").click()
    app.run(timeout=15)
    assert any(value.value == "Operator recovery checkpoint" for value in app.header)

    next(button for button in app.button if button.label == "Acknowledge Investigation").click()
    app.run(timeout=15)
    assert any("signed six-event evidence ledger is valid" in value.value for value in app.success)

    next(button for button in app.button if button.label == "Open Signed Evidence Review").click()
    app.run(timeout=15)
    assert app.title[0].value == "VERITAS-AI Signed Evidence Review"
