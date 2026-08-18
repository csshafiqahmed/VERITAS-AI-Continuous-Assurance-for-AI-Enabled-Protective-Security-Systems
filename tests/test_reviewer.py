import io
import subprocess
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest

import veritas_ai.reviewer as reviewer
from veritas_ai.io import write_json
from veritas_ai.ledger import sign_events, write_verification_report
from veritas_ai.reviewer import (
    build_reviewer_archive,
    create_reviewer_run,
    discover_completed_runs,
    load_verified_run,
    reviewer_preflight,
    safe_tamper_test,
)


def _completed_run(root: Path) -> Path:
    run_dir = root / "20260818T040000Z-test"
    data_dir = run_dir / "data"
    model_dir = run_dir / "model"
    data_dir.mkdir(parents=True)
    model_dir.mkdir()
    (model_dir / "model.json").write_text("{}\n", encoding="utf-8")
    write_json(
        model_dir / "model_manifest.json",
        {"schema_version": "1.1.0", "model_sha256": "a" * 64},
    )
    write_json(data_dir / "dataset_manifest.json", {"schema_version": "1.1.0"})
    (data_dir / "traffic.pcap").write_bytes(b"safe synthetic PCAP")
    write_json(
        run_dir / "baseline.json",
        {
            "schema_version": "1.1.0",
            "model_sha256": "a" * 64,
            "policy_sha256": "b" * 64,
        },
    )
    events = [
        {
            "scenario": "stable_operation",
            "action": "continue",
            "reasons": ["inside_reference_envelope"],
            "sample_count": 250,
            "labels_available": True,
            "maximum_psi": 0.02,
            "feature_psi": {},
            "telemetry_missingness": 0.0,
            "confidence_cusum_sigma": 0.0,
            "inference_latency_ms": 1.0,
            "integrity": {"model_matches": True, "policy_matches": True},
        }
    ]
    ledger = run_dir / "assurance_events.jsonl"
    public_key = run_dir / "public_key.pem"
    sign_events(events, ledger, public_key)
    report = write_verification_report(ledger, public_key, run_dir / "verification_report.json")
    write_json(
        run_dir / "run_summary.json",
        {
            "schema_version": "1.1.0",
            "version": "0.2.0",
            "seed": 42,
            "git_revision": "unavailable",
            "trl_claim": "Evidence consistent with TRL 3 laboratory proof of concept",
            "limitations": ["not_trl_6"],
            "demonstration": {
                "mode": "guided_reviewer",
                "telemetry_source": "synthetic_zeek_compatible",
                "zeek_validated": False,
                "operator_acknowledged": True,
                "recovery_window_count": 2,
            },
            "dataset_manifest": {"zeek_mode": "synthetic_zeek_compatible"},
            "model_manifest": {"model_sha256": "a" * 64, "classes": []},
            "scenario_actions": {"stable_operation": "continue"},
            "ledger_valid": report["valid"],
            "artifacts": {},
        },
    )
    return run_dir


def test_portable_preflight_and_unique_run_directory(tmp_path: Path) -> None:
    runs_root = tmp_path / "reviewer"
    report = reviewer_preflight(runs_root, require_zeek=False)

    assert report.ready is True
    assert all(check.status != "fail" for check in report.checks)
    first = create_reviewer_run(runs_root)
    second = create_reviewer_run(runs_root)
    assert first != second
    assert first.parent == runs_root.resolve()
    assert second.parent == runs_root.resolve()

    blocked = reviewer_preflight(
        runs_root,
        require_zeek=False,
        another_run_active=True,
    )
    assert blocked.ready is False


def test_preflight_rejects_low_storage_and_missing_library(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_find_spec = reviewer.importlib.util.find_spec
    monkeypatch.setattr(
        reviewer.shutil,
        "disk_usage",
        lambda path: SimpleNamespace(free=1),
    )
    monkeypatch.setattr(
        reviewer.importlib.util,
        "find_spec",
        lambda name: None if name == "xgboost" else original_find_spec(name),
    )

    report = reviewer_preflight(tmp_path / "runs", require_zeek=False)

    assert report.ready is False
    assert {check.name for check in report.checks if check.status == "fail"} == {
        "Free storage",
        "Required libraries",
    }


def test_zeek_preflight_covers_docker_failure_and_image_states(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runs_root = tmp_path / "runs"
    monkeypatch.setattr(reviewer.shutil, "which", lambda name: None)
    missing = reviewer_preflight(runs_root, require_zeek=True)
    assert missing.ready is False
    assert next(check for check in missing.checks if check.name == "Zeek route").status == "fail"

    monkeypatch.setattr(reviewer.shutil, "which", lambda name: "/usr/bin/docker")

    def timed_out(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired("docker", 5)

    monkeypatch.setattr(reviewer.subprocess, "run", timed_out)
    timeout = reviewer_preflight(runs_root, require_zeek=True)
    assert timeout.ready is False

    def daemon_failure(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 1, stdout="", stderr="daemon unavailable")

    monkeypatch.setattr(reviewer.subprocess, "run", daemon_failure)
    unavailable = reviewer_preflight(runs_root, require_zeek=True)
    assert unavailable.ready is False

    def image_state(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0 if command[1] == "info" else 1)

    monkeypatch.setattr(reviewer.subprocess, "run", image_state)
    fetch_required = reviewer_preflight(runs_root, require_zeek=True)
    assert fetch_required.ready is True
    assert (
        next(check for check in fetch_required.checks if check.name == "Zeek route").status
        == "warning"
    )

    def image_local(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(reviewer.subprocess, "run", image_local)
    local = reviewer_preflight(runs_root, require_zeek=True)
    assert local.ready is True
    assert next(check for check in local.checks if check.name == "Zeek route").status == "pass"


def test_only_reconciled_completed_runs_are_discovered(tmp_path: Path) -> None:
    runs_root = tmp_path / "runs"
    completed = _completed_run(runs_root)
    partial = runs_root / "partial"
    partial.mkdir()
    write_json(partial / "run_summary.json", {"ledger_valid": True})

    assert discover_completed_runs(runs_root) == [completed]
    loaded = load_verified_run(completed)
    assert loaded["verification"]["valid"] is True
    assert loaded["scenario_actions"] == {"stable_operation": "continue"}


def test_reviewer_archives_exclude_internal_state_and_private_keys(tmp_path: Path) -> None:
    run_dir = _completed_run(tmp_path / "runs")
    write_json(run_dir / ".guided-state.json", {"phase": "completed"})

    compact = build_reviewer_archive(run_dir, full=False)
    full = build_reviewer_archive(run_dir, full=True)
    for payload in (compact, full):
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
            names = archive.getnames()
        assert any(name.endswith("/public_key.pem") for name in names)
        assert not any(".guided-state.json" in name for name in names)
        assert not any(name.endswith("private_key.pem") for name in names)
    with tarfile.open(fileobj=io.BytesIO(full), mode="r:gz") as archive:
        assert any(name.endswith("/data/traffic.pcap") for name in archive.getnames())


def test_full_archive_rejects_private_key_material(tmp_path: Path) -> None:
    run_dir = _completed_run(tmp_path / "runs")
    begin_marker = b"-----BEGIN " + b"PRIVATE KEY-----"
    end_marker = b"-----END " + b"PRIVATE KEY-----"
    (run_dir / "model" / "unsafe.bin").write_bytes(
        begin_marker + b"\nsecret\n" + end_marker + b"\n"
    )

    with pytest.raises(ValueError, match="Private key material"):
        build_reviewer_archive(run_dir, full=True)


def test_safe_tamper_test_preserves_canonical_evidence(tmp_path: Path) -> None:
    run_dir = _completed_run(tmp_path / "runs")

    result = safe_tamper_test(run_dir)

    assert result["canonical_valid"] is True
    assert result["canonical_unchanged"] is True
    assert result["tampered_valid"] is False
    assert result["tampered_error"] == "Hash mismatch at line 1"
    assert result["changed_field"] == "maximum_psi"
