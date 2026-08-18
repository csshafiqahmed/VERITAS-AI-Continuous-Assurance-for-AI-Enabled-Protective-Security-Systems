import io
import subprocess
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest

import veritas_ai.reviewer as reviewer
from veritas_ai.io import sha256_file, write_json
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
    model_path = model_dir / "model.json"
    model_path.write_text("{}\n", encoding="utf-8")
    model_manifest = {
        "schema_version": "1.1.0",
        "model_sha256": sha256_file(model_path),
        "classes": [],
    }
    write_json(model_dir / "model_manifest.json", model_manifest)
    (data_dir / "traffic.pcap").write_bytes(b"safe synthetic PCAP")
    (data_dir / "auth.jsonl").write_text("{}\n", encoding="utf-8")
    dataset_manifest = {
        "schema_version": "1.1.0",
        "zeek_mode": "synthetic_zeek_compatible",
        "files": {
            "traffic.pcap": sha256_file(data_dir / "traffic.pcap"),
            "auth.jsonl": sha256_file(data_dir / "auth.jsonl"),
        },
    }
    write_json(data_dir / "dataset_manifest.json", dataset_manifest)
    baseline = {
        "schema_version": "1.1.0",
        "model_sha256": model_manifest["model_sha256"],
        "policy_sha256": "b" * 64,
    }
    write_json(run_dir / "baseline.json", baseline)
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
    demonstration = {
        "mode": "guided_reviewer",
        "telemetry_source": "synthetic_zeek_compatible",
        "zeek_validated": False,
        "operator_acknowledged": True,
        "recovery_window_count": 2,
    }
    limitations = ["not_trl_6"]
    bindings = {
        "schema_version": "1.1.0",
        "version": "0.2.0",
        "git_revision": "unavailable",
        "python": "3.12.3",
        "seed": 42,
        "trl_claim": "Evidence consistent with TRL 3 laboratory proof of concept",
        "limitations": limitations,
        "demonstration": demonstration,
        "artifacts": {
            name: sha256_file(run_dir / name)
            for name in (
                "baseline.json",
                "data/dataset_manifest.json",
                "model/model.json",
                "model/model_manifest.json",
            )
        },
    }
    sign_events(events, ledger, public_key, evidence_bindings=bindings)
    report = write_verification_report(ledger, public_key, run_dir / "verification_report.json")
    artifact_names = (
        "baseline.json",
        "assurance_events.jsonl",
        "public_key.pem",
        "verification_report.json",
        "data/dataset_manifest.json",
        "model/model.json",
        "model/model_manifest.json",
    )
    write_json(
        run_dir / "run_summary.json",
        {
            "schema_version": "1.1.0",
            "version": "0.2.0",
            "seed": 42,
            "git_revision": "unavailable",
            "python": "3.12.3",
            "trl_claim": bindings["trl_claim"],
            "limitations": limitations,
            "demonstration": demonstration,
            "dataset_manifest": dataset_manifest,
            "model_manifest": model_manifest,
            "scenario_actions": {"stable_operation": "continue"},
            "ledger_valid": report["valid"],
            "artifacts": {name: sha256_file(run_dir / name) for name in artifact_names},
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


@pytest.mark.parametrize(
    "relative_path",
    ["baseline.json", "model/model.json", "data/auth.jsonl"],
)
def test_verified_run_rejects_modified_bound_or_manifest_artifact(
    tmp_path: Path,
    relative_path: str,
) -> None:
    run_dir = _completed_run(tmp_path / "runs")
    path = run_dir / relative_path
    path.write_bytes(path.read_bytes() + b"\n")

    with pytest.raises(ValueError, match=r"hash|binding|manifest|Model artifact"):
        load_verified_run(run_dir)


def test_verified_run_rejects_modified_signed_summary_metadata(tmp_path: Path) -> None:
    run_dir = _completed_run(tmp_path / "runs")
    summary = reviewer.read_json(run_dir / "run_summary.json")
    summary["seed"] = 7
    write_json(run_dir / "run_summary.json", summary)

    with pytest.raises(ValueError, match="not bound by the ledger, seed"):
        load_verified_run(run_dir)


def test_verified_run_rejects_symlinked_baseline(tmp_path: Path) -> None:
    run_dir = _completed_run(tmp_path / "runs")
    baseline = run_dir / "baseline.json"
    copied = run_dir / "baseline-copy.json"
    copied.write_bytes(baseline.read_bytes())
    baseline.unlink()
    baseline.symlink_to(copied.name)

    with pytest.raises(ValueError, match=r"regular file at baseline\.json"):
        load_verified_run(run_dir)


def test_verified_run_rejects_mismatched_stored_verification(tmp_path: Path) -> None:
    run_dir = _completed_run(tmp_path / "runs")
    report_path = run_dir / "verification_report.json"
    report = reviewer.read_json(report_path)
    report["events_checked"] = 99
    write_json(report_path, report)

    with pytest.raises(ValueError, match="verification report"):
        load_verified_run(run_dir)


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("schema", "schema versions do not match"),
        ("dataset_summary", "dataset manifest does not match"),
        ("model_summary", "model manifest does not match"),
        ("baseline_model", "Baseline and model manifest"),
        ("ledger_valid", "does not record a valid ledger"),
    ],
)
def test_verified_run_rejects_cross_artifact_inconsistency(
    tmp_path: Path,
    case: str,
    message: str,
) -> None:
    run_dir = _completed_run(tmp_path / "runs")
    summary_path = run_dir / "run_summary.json"
    summary = reviewer.read_json(summary_path)
    if case == "schema":
        summary["schema_version"] = "1.0"
    elif case == "dataset_summary":
        summary["dataset_manifest"] = {"schema_version": "1.1.0"}
    elif case == "model_summary":
        summary["model_manifest"] = {"schema_version": "1.1.0"}
    elif case == "baseline_model":
        baseline_path = run_dir / "baseline.json"
        baseline = reviewer.read_json(baseline_path)
        baseline["model_sha256"] = "f" * 64
        write_json(baseline_path, baseline)
    else:
        summary["ledger_valid"] = False
    write_json(summary_path, summary)

    with pytest.raises(ValueError, match=message):
        load_verified_run(run_dir)


def test_verified_run_rejects_missing_summary_artifact_hash(tmp_path: Path) -> None:
    run_dir = _completed_run(tmp_path / "runs")
    summary_path = run_dir / "run_summary.json"
    summary = reviewer.read_json(summary_path)
    summary["artifacts"].pop("model/model.json")
    write_json(summary_path, summary)

    with pytest.raises(ValueError, match="missing required artifact hashes"):
        load_verified_run(run_dir)


@pytest.mark.parametrize(
    ("files", "message"),
    [
        ({}, "does not contain file hashes"),
        ({"../outside.json": "a" * 64}, "Invalid evidence path"),
        ({"missing/file.json": "a" * 64}, "invalid directory"),
    ],
)
def test_verified_run_rejects_unsafe_dataset_inventory(
    tmp_path: Path,
    files: dict[str, str],
    message: str,
) -> None:
    run_dir = _completed_run(tmp_path / "runs")
    manifest_path = run_dir / "data" / "dataset_manifest.json"
    manifest = reviewer.read_json(manifest_path)
    manifest["files"] = files
    write_json(manifest_path, manifest)
    summary_path = run_dir / "run_summary.json"
    summary = reviewer.read_json(summary_path)
    summary["dataset_manifest"] = manifest
    write_json(summary_path, summary)

    with pytest.raises(ValueError, match=message):
        load_verified_run(run_dir)
