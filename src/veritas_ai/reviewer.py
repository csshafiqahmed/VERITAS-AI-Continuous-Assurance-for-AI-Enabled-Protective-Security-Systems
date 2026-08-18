"""Safety and evidence helpers for the guided reviewer application."""

from __future__ import annotations

import gzip
import importlib.util
import io
import os
import shutil
import subprocess
import tarfile
import tempfile
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from veritas_ai.constants import SCHEMA_VERSION, ZEEK_IMAGE
from veritas_ai.io import read_json, read_jsonl, sha256_file, write_jsonl
from veritas_ai.ledger import verify_ledger

MINIMUM_FREE_BYTES = 250 * 1024 * 1024
_COMPACT_PATHS = (
    "assurance_events.jsonl",
    "baseline.json",
    "data/dataset_manifest.json",
    "model/model.json",
    "model/model_manifest.json",
    "public_key.pem",
    "run_summary.json",
    "verification_report.json",
)
_TOP_LEVEL_EVIDENCE = frozenset(
    {
        "assurance_events.jsonl",
        "baseline.json",
        "public_key.pem",
        "run_summary.json",
        "verification_report.json",
    }
)
_PRIVATE_KEY_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
)
_REQUIRED_EVIDENCE_PATHS = (
    "run_summary.json",
    "assurance_events.jsonl",
    "public_key.pem",
    "baseline.json",
    "data/dataset_manifest.json",
    "model/model.json",
    "model/model_manifest.json",
    "verification_report.json",
)
_CURRENT_SUMMARY_ARTIFACTS = frozenset(
    {
        "baseline.json",
        "assurance_events.jsonl",
        "public_key.pem",
        "verification_report.json",
        "data/dataset_manifest.json",
        "model/model.json",
        "model/model_manifest.json",
    }
)
_LEGACY_SUMMARY_ARTIFACTS = frozenset(
    {
        "baseline.json",
        "assurance_events.jsonl",
        "public_key.pem",
        "verification_report.json",
    }
)
_BOUND_ARTIFACTS = frozenset(
    {
        "baseline.json",
        "data/dataset_manifest.json",
        "model/model.json",
        "model/model_manifest.json",
    }
)
_BOUND_SUMMARY_FIELDS = (
    "schema_version",
    "version",
    "git_revision",
    "python",
    "seed",
    "trl_claim",
    "limitations",
    "demonstration",
)


@dataclass(frozen=True, slots=True)
class PreflightCheck:
    name: str
    status: Literal["pass", "warning", "fail"]
    detail: str
    blocking: bool

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class PreflightReport:
    ready: bool
    checks: tuple[PreflightCheck, ...]

    def rows(self) -> list[dict[str, Any]]:
        return [check.as_dict() for check in self.checks]


def reviewer_preflight(
    runs_root: Path,
    *,
    require_zeek: bool,
    another_run_active: bool = False,
    minimum_free_bytes: int = MINIMUM_FREE_BYTES,
) -> PreflightReport:
    """Check the bounded local requirements before starting a guided run."""
    checks: list[PreflightCheck] = []
    try:
        runs_root.mkdir(parents=True, exist_ok=True)
        resolved_root = runs_root.resolve(strict=True)
        writable = resolved_root.is_dir() and os.access(resolved_root, os.W_OK)
    except OSError as error:
        resolved_root = runs_root.resolve(strict=False)
        writable = False
        checks.append(
            PreflightCheck("Run storage", "fail", f"Storage setup failed with {error}", True)
        )
    else:
        checks.append(
            PreflightCheck(
                "Run storage",
                "pass" if writable else "fail",
                f"Reviewer runs use {resolved_root}",
                not writable,
            )
        )

    if writable:
        free_bytes = shutil.disk_usage(resolved_root).free
        enough_storage = free_bytes >= minimum_free_bytes
        checks.append(
            PreflightCheck(
                "Free storage",
                "pass" if enough_storage else "fail",
                f"{free_bytes / (1024 * 1024):,.0f} MB available, 250 MB required",
                not enough_storage,
            )
        )
        candidate = (resolved_root / "preflight-path-check").resolve(strict=False)
        path_safe = candidate.is_relative_to(resolved_root)
        checks.append(
            PreflightCheck(
                "Output-path boundary",
                "pass" if path_safe else "fail",
                "Generated runs remain beneath the configured run root",
                not path_safe,
            )
        )

    required_modules = ("cryptography", "sklearn", "streamlit", "xgboost")
    missing_modules = [name for name in required_modules if importlib.util.find_spec(name) is None]
    checks.append(
        PreflightCheck(
            "Required libraries",
            "pass" if not missing_modules else "fail",
            "All model, dashboard, and cryptographic libraries are available"
            if not missing_modules
            else f"Missing libraries include {', '.join(missing_modules)}",
            bool(missing_modules),
        )
    )

    checks.append(
        PreflightCheck(
            "Active demonstration",
            "fail" if another_run_active else "pass",
            "Another reviewer run is active"
            if another_run_active
            else "No other reviewer run is active",
            another_run_active,
        )
    )

    if not require_zeek:
        checks.append(
            PreflightCheck(
                "Zeek route",
                "pass",
                "Portable generated Zeek-format records are selected",
                False,
            )
        )
    elif shutil.which("docker") is None:
        checks.append(
            PreflightCheck("Zeek route", "fail", "Docker is not installed or not on PATH", True)
        )
    else:
        try:
            daemon = subprocess.run(
                ["docker", "info", "--format", "{{.ServerVersion}}"],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            checks.append(
                PreflightCheck("Zeek route", "fail", f"Docker check failed with {error}", True)
            )
        else:
            if daemon.returncode != 0:
                detail = (daemon.stderr or daemon.stdout).strip() or "Docker daemon is unavailable"
                checks.append(PreflightCheck("Zeek route", "fail", detail, True))
            else:
                try:
                    image = subprocess.run(
                        ["docker", "image", "inspect", ZEEK_IMAGE],
                        check=False,
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                except (OSError, subprocess.TimeoutExpired):
                    image = None
                if image is not None and image.returncode == 0:
                    checks.append(
                        PreflightCheck(
                            "Zeek route",
                            "pass",
                            "Docker is ready and the digest-pinned Zeek image is local",
                            False,
                        )
                    )
                else:
                    checks.append(
                        PreflightCheck(
                            "Zeek route",
                            "warning",
                            "Docker is ready. The pinned image will be fetched during the run",
                            False,
                        )
                    )

    return PreflightReport(
        ready=not any(check.blocking for check in checks),
        checks=tuple(checks),
    )


def create_reviewer_run(runs_root: Path) -> Path:
    """Create a unique run directory beneath the configured root."""
    resolved_root = runs_root.resolve(strict=True)
    run_name = f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"
    output = (resolved_root / run_name).resolve(strict=False)
    if not output.is_relative_to(resolved_root):
        raise ValueError("Reviewer output escaped its configured run root")
    output.mkdir(mode=0o700)
    return output


def _regular_file_beneath(root: Path, relative_name: str) -> Path:
    """Resolve a regular non-symlink file without permitting path traversal."""
    relative = PurePosixPath(relative_name)
    if (
        not relative.parts
        or relative.is_absolute()
        or any(part in {"", ".", ".."} for part in relative.parts)
        or "\\" in relative_name
    ):
        raise ValueError(f"Invalid evidence path, {relative_name}")
    current = root
    for part in relative.parts[:-1]:
        current /= part
        if current.is_symlink() or not current.is_dir():
            raise ValueError(f"Evidence path contains an invalid directory, {relative_name}")
    candidate = root.joinpath(*relative.parts)
    if candidate.is_symlink() or not candidate.is_file():
        raise ValueError(f"Evidence requires a regular file at {relative_name}")
    if not candidate.resolve(strict=True).is_relative_to(root.resolve(strict=True)):
        raise ValueError(f"Evidence path escapes the run directory, {relative_name}")
    return candidate


def _validate_dataset_files(run_dir: Path, manifest: dict[str, Any]) -> None:
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise ValueError("Dataset manifest does not contain file hashes")
    data_root = run_dir / "data"
    for name, expected_hash in files.items():
        if not isinstance(name, str) or not isinstance(expected_hash, str):
            raise ValueError("Dataset manifest contains an invalid file-hash entry")
        path = _regular_file_beneath(data_root, name)
        if sha256_file(path) != expected_hash:
            raise ValueError(f"Dataset artifact hash does not match for {name}")


def _validate_summary_artifacts(
    run_dir: Path,
    summary: dict[str, Any],
    *,
    current_schema: bool,
) -> None:
    artifacts = summary.get("artifacts")
    if not isinstance(artifacts, dict):
        raise ValueError("Run summary does not contain an artifact index")
    required = _CURRENT_SUMMARY_ARTIFACTS if current_schema else _LEGACY_SUMMARY_ARTIFACTS
    if not required.issubset(artifacts):
        raise ValueError("Run summary is missing required artifact hashes")
    for name, expected_hash in artifacts.items():
        if not isinstance(name, str) or not isinstance(expected_hash, str):
            raise ValueError("Run summary contains an invalid artifact-hash entry")
        path = _regular_file_beneath(run_dir, name)
        if sha256_file(path) != expected_hash:
            raise ValueError(f"Run summary artifact hash does not match for {name}")


def _validate_stored_verification(
    stored: dict[str, Any],
    fresh: dict[str, Any],
    *,
    current_schema: bool,
) -> None:
    if current_schema:
        if stored != fresh:
            raise ValueError("Stored verification report does not match fresh verification")
        return
    for field in ("valid", "events_checked", "error", "ledger_sha256"):
        if stored.get(field) != fresh.get(field):
            raise ValueError("Legacy verification report does not match fresh verification")


def _validate_signed_bindings(
    run_dir: Path,
    summary: dict[str, Any],
    verification: dict[str, Any],
) -> None:
    bindings = verification.get("evidence_bindings")
    if not isinstance(bindings, dict):
        raise ValueError("Current evidence is missing signed artifact bindings")
    for field in _BOUND_SUMMARY_FIELDS:
        if bindings.get(field) != summary.get(field):
            raise ValueError(f"Run summary field is not bound by the ledger, {field}")
    artifacts = bindings.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != _BOUND_ARTIFACTS:
        raise ValueError("Signed artifact bindings are incomplete")
    for name, expected_hash in artifacts.items():
        if not isinstance(expected_hash, str):
            raise ValueError(f"Signed artifact binding is invalid for {name}")
        path = _regular_file_beneath(run_dir, str(name))
        if sha256_file(path) != expected_hash:
            raise ValueError(f"Signed artifact binding does not match for {name}")


def load_verified_run(run_dir: Path) -> dict[str, Any]:
    """Load display evidence only after cryptographic and summary reconciliation."""
    if run_dir.is_symlink():
        raise ValueError("Evidence path cannot be a symlink")
    resolved = run_dir.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError("Evidence path is not a directory")
    for directory in (resolved / "data", resolved / "model"):
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError(f"Completed evidence requires a regular directory at {directory.name}")
    required = {name: _regular_file_beneath(resolved, name) for name in _REQUIRED_EVIDENCE_PATHS}
    summary = read_json(required["run_summary.json"])
    verification = verify_ledger(
        required["assurance_events.jsonl"],
        required["public_key.pem"],
    )
    if not verification["valid"]:
        raise ValueError(f"Dashboard refused an invalid evidence ledger, {verification['error']}")

    ledger_schema = verification.get("ledger_schema_version")
    summary_schema = summary.get("schema_version", "1.0")
    if summary_schema != ledger_schema:
        raise ValueError("Run summary and signed ledger schema versions do not match")
    current_schema = ledger_schema == SCHEMA_VERSION

    dataset_manifest = read_json(required["data/dataset_manifest.json"])
    model_manifest = read_json(required["model/model_manifest.json"])
    baseline = read_json(required["baseline.json"])
    if summary.get("dataset_manifest") != dataset_manifest:
        raise ValueError("Run summary dataset manifest does not match its artifact")
    if summary.get("model_manifest") != model_manifest:
        raise ValueError("Run summary model manifest does not match its artifact")
    _validate_dataset_files(resolved, dataset_manifest)
    if sha256_file(required["model/model.json"]) != model_manifest.get("model_sha256"):
        raise ValueError("Model artifact does not match its manifest")
    if baseline.get("model_sha256") != model_manifest.get("model_sha256"):
        raise ValueError("Baseline and model manifest do not identify the same model")

    stored_verification = read_json(required["verification_report.json"])
    _validate_stored_verification(
        stored_verification,
        verification,
        current_schema=current_schema,
    )
    _validate_summary_artifacts(resolved, summary, current_schema=current_schema)
    if current_schema:
        _validate_signed_bindings(resolved, summary, verification)

    events: list[dict[str, Any]] = []
    for index, record in enumerate(read_jsonl(required["assurance_events.jsonl"]), start=1):
        if record.get("record_type") == "seal":
            continue
        event = record.get("event")
        if not isinstance(event, dict):
            raise ValueError(f"Ledger record {index} does not contain an event object")
        events.append(event)
    if len(events) != verification["events_checked"]:
        raise ValueError("Verified event count does not match the displayed event count")

    scenario_actions = {str(event["scenario"]): str(event["action"]) for event in events}
    if summary.get("scenario_actions") != scenario_actions:
        raise ValueError("Run summary decisions do not match the signed ledger")
    if summary.get("ledger_valid") is not True:
        raise ValueError("Run summary does not record a valid ledger")
    return {
        "run_dir": resolved,
        "summary": summary,
        "verification": verification,
        "events": events,
        "scenario_actions": scenario_actions,
    }


def discover_completed_runs(runs_root: Path) -> list[Path]:
    """Return valid completed child runs without exposing failed or partial work."""
    try:
        resolved_root = runs_root.resolve(strict=True)
    except FileNotFoundError:
        return []
    completed: list[Path] = []
    for candidate in sorted(resolved_root.iterdir(), reverse=True):
        if not candidate.is_dir() or candidate.is_symlink():
            continue
        try:
            load_verified_run(candidate)
        except (OSError, KeyError, TypeError, ValueError):
            continue
        completed.append(candidate)
    return completed


def _contains_private_key(path: Path) -> bool:
    carry = b""
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            sample = carry + chunk
            if any(marker in sample for marker in _PRIVATE_KEY_MARKERS):
                return True
            carry = sample[-64:]
    return False


def _normalised_info(path: Path, name: str) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = path.stat().st_size
    info.mode = 0o644
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    return info


def _archive_paths(run_dir: Path, *, full: bool) -> list[Path]:
    if not full:
        paths = [run_dir / name for name in _COMPACT_PATHS]
    else:
        paths = [run_dir / name for name in _TOP_LEVEL_EVIDENCE]
        for directory in (run_dir / "data", run_dir / "model"):
            paths.extend(path for path in directory.rglob("*") if path.is_file())
    unique = sorted(set(paths))
    for path in unique:
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"Evidence archive requires a regular file at {path}")
        relative = PurePosixPath(path.relative_to(run_dir).as_posix())
        if any(part.startswith(".") for part in relative.parts):
            raise ValueError(f"Internal file cannot enter the evidence archive, {relative}")
        if path.suffix.casefold() in {".key", ".pem"} and path.name != "public_key.pem":
            raise ValueError(f"Private key path cannot enter the evidence archive, {relative}")
        if _contains_private_key(path):
            raise ValueError(f"Private key material detected in {relative}")
    return unique


def build_reviewer_archive(run_dir: Path, *, full: bool) -> bytes:
    """Create an on-demand normalised archive from verified evidence."""
    verified = load_verified_run(run_dir)
    resolved = Path(verified["run_dir"])
    prefix = f"veritas-ai-{resolved.name}-{'full' if full else 'compact'}"
    output = io.BytesIO()
    with (
        gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as compressed,
        tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive,
    ):
        for path in _archive_paths(resolved, full=full):
            relative = path.relative_to(resolved).as_posix()
            with path.open("rb") as handle:
                archive.addfile(_normalised_info(path, f"{prefix}/{relative}"), handle)
    return output.getvalue()


def safe_tamper_test(run_dir: Path) -> dict[str, Any]:
    """Modify a temporary ledger copy and prove that verification rejects it."""
    verified = load_verified_run(run_dir)
    resolved = Path(verified["run_dir"])
    ledger = resolved / "assurance_events.jsonl"
    public_key = resolved / "public_key.pem"
    original_before = sha256_file(ledger)
    records = read_jsonl(ledger)
    changed_field = ""
    original_value = 0.0
    changed_value = 0.0
    for record in records:
        if record.get("record_type") != "event":
            continue
        event = record.get("event")
        if isinstance(event, dict) and isinstance(event.get("maximum_psi"), (int, float)):
            changed_field = "maximum_psi"
            original_value = float(event[changed_field])
            changed_value = original_value + 0.001
            event[changed_field] = changed_value
            break
    if not changed_field:
        raise ValueError("No numeric assurance metric is available for the tamper test")

    with tempfile.TemporaryDirectory(prefix="veritas-ai-tamper-") as directory:
        temporary = Path(directory)
        copied_ledger = temporary / "assurance_events.jsonl"
        copied_key = temporary / "public_key.pem"
        write_jsonl(copied_ledger, records)
        copied_key.write_bytes(public_key.read_bytes())
        tampered_report = verify_ledger(copied_ledger, copied_key)

    original_after = sha256_file(ledger)
    original_report = verify_ledger(ledger, public_key)
    return {
        "canonical_valid": bool(original_report["valid"]),
        "canonical_unchanged": original_before == original_after,
        "canonical_sha256": original_after,
        "tampered_valid": bool(tampered_report["valid"]),
        "tampered_error": tampered_report["error"],
        "changed_field": changed_field,
        "original_value": original_value,
        "changed_value": changed_value,
    }
