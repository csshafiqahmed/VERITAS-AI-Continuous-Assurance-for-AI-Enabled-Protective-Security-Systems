"""Staged TRL 3 demonstration workflow and reviewer checkpoint."""

from __future__ import annotations

import platform
import subprocess
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from veritas_ai import __version__
from veritas_ai.assurance import create_baseline, monitor_records
from veritas_ai.constants import (
    DEFAULT_SEED,
    SCHEMA_VERSION,
    SUPPORTED_SCHEMA_VERSIONS,
    THRESHOLDS,
    ZEEK_IMAGE,
)
from veritas_ai.data import SCENARIOS, generate_dataset, process_with_zeek
from veritas_ai.io import (
    canonical_json,
    read_json,
    read_jsonl,
    sha256_bytes,
    sha256_file,
    write_json,
)
from veritas_ai.ledger import sign_events, write_verification_report
from veritas_ai.model import train_model

ProgressState = Literal["started", "advanced", "completed", "awaiting_input", "failed"]
DemoMode = Literal["automatic_cli", "guided_reviewer"]
ProgressObserver = Callable[["ProgressEvent"], None]

RUN_STATE_NAME = ".guided-state.json"
FIRST_PHASE_SCENARIOS = SCENARIOS[:-1]
RECOVERY_SCENARIO = "recovery_after_investigation"
_ACTION_SEVERITY = {"continue": 0, "investigate": 1, "recalibrate": 2, "withdraw": 3}
_BOUND_ARTIFACTS = (
    "baseline.json",
    "data/dataset_manifest.json",
    "model/model.json",
    "model/model_manifest.json",
)
_LIMITATIONS = [
    "synthetic_data",
    "no_external_partner_validation",
    "no_representative_operational_environment",
    "not_trl_6",
]


@dataclass(frozen=True, slots=True)
class ProgressEvent:
    """Internal observation of completed workflow work."""

    sequence: int
    stage: str
    state: ProgressState
    message: str
    elapsed_seconds: float
    current: int | None = None
    total: int | None = None
    artifact: str | None = None
    artifact_sha256: str | None = None
    action: str | None = None
    reason: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class _ProgressEmitter:
    def __init__(
        self,
        observer: ProgressObserver | None,
        *,
        sequence: int = 0,
        elapsed_offset: float = 0.0,
    ) -> None:
        self._observer = observer
        self._sequence = sequence
        self._elapsed_offset = elapsed_offset
        self._started = time.perf_counter()

    @property
    def sequence(self) -> int:
        return self._sequence

    @property
    def elapsed_seconds(self) -> float:
        return self._elapsed_offset + time.perf_counter() - self._started

    def emit(
        self,
        stage: str,
        state: ProgressState,
        message: str,
        *,
        current: int | None = None,
        total: int | None = None,
        artifact: str | None = None,
        artifact_sha256: str | None = None,
        action: str | None = None,
        reason: str | None = None,
    ) -> ProgressEvent:
        if current is not None and total is not None and not 0 <= current <= total:
            raise ValueError("Progress current value must remain inside its declared total")
        self._sequence += 1
        event = ProgressEvent(
            sequence=self._sequence,
            stage=stage,
            state=state,
            message=message,
            elapsed_seconds=self.elapsed_seconds,
            current=current,
            total=total,
            artifact=artifact,
            artifact_sha256=artifact_sha256,
            action=action,
            reason=reason,
        )
        if self._observer is not None:
            self._observer(event)
        return event


def _git_revision() -> str:
    project_root = Path(__file__).resolve().parents[2]
    source_file = project_root / "src" / "veritas_ai" / "workflow.py"
    if (
        not (project_root / "pyproject.toml").is_file()
        or not source_file.is_file()
        or source_file.resolve() != Path(__file__).resolve()
    ):
        return "unavailable"
    try:
        root_result = subprocess.run(
            ["git", "-C", str(project_root), "rev-parse", "--show-toplevel"],
            check=False,
            capture_output=True,
            text=True,
        )
        if (
            root_result.returncode != 0
            or Path(root_result.stdout.strip()).resolve() != project_root
        ):
            return "unavailable"
        result = subprocess.run(
            ["git", "-C", str(project_root), "rev-parse", "--verify", "HEAD^{commit}"],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return "unavailable"
    return result.stdout.strip() if result.returncode == 0 else "unavailable"


def _write_run_state(
    output: Path,
    *,
    phase: str,
    mode: DemoMode,
    regenerate_zeek: bool,
    seed: int,
    emitter: _ProgressEmitter,
    started_at: str,
    provisional_actions: dict[str, str] | None = None,
    provisional_evidence_sha256: str | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    state: dict[str, Any] = {
        "internal_format": 1,
        "phase": phase,
        "mode": mode,
        "regenerate_zeek": regenerate_zeek,
        "seed": seed,
        "started_at": started_at,
        "updated_at": datetime.now(UTC).isoformat(),
        "progress_sequence": emitter.sequence,
        "elapsed_seconds": emitter.elapsed_seconds,
        "provisional_actions": provisional_actions or {},
        "provisional_evidence_sha256": provisional_evidence_sha256,
        "error": error,
    }
    write_json(output / RUN_STATE_NAME, state)
    return state


def read_guided_state(output: Path) -> dict[str, Any]:
    """Read local workflow state without treating it as signed evidence."""
    state = read_json(output / RUN_STATE_NAME)
    if state.get("internal_format") != 1:
        raise ValueError("Unsupported guided-run state format")
    return state


def _clear_completion_markers(output: Path) -> None:
    for name in (
        "assurance_events.jsonl",
        "public_key.pem",
        "verification_report.json",
        "run_summary.json",
    ):
        path = output / name
        if path.is_file():
            path.unlink()


def _scenario_parameters(scenario: str) -> dict[str, Any]:
    if scenario == "benign_workload_change":
        return {"context_approved": True}
    if scenario == "model_replacement":
        return {"observed_model_hash": "0" * 64}
    return {}


def _evaluate_scenario(
    model_dir: Path,
    baseline_path: Path,
    records: list[dict[str, Any]],
    scenario: str,
) -> dict[str, Any]:
    scenario_records = [record for record in records if record.get("scenario") == scenario]
    return monitor_records(
        model_dir,
        baseline_path,
        scenario_records,
        labels_available=scenario != "partial_telemetry_loss",
        **_scenario_parameters(scenario),
    )


def _evaluate_first_phase(
    model_dir: Path,
    baseline_path: Path,
    records: list[dict[str, Any]],
    emitter: _ProgressEmitter | None = None,
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for position, scenario in enumerate(FIRST_PHASE_SCENARIOS, start=1):
        if emitter is not None:
            emitter.emit(
                "scenario_monitoring",
                "started",
                f"Evaluating {scenario.replace('_', ' ')}",
                current=position - 1,
                total=len(SCENARIOS),
            )
        event = _evaluate_scenario(model_dir, baseline_path, records, scenario)
        events.append(event)
        if emitter is not None:
            emitter.emit(
                "scenario_monitoring",
                "advanced",
                f"Completed {scenario.replace('_', ' ')}",
                current=position,
                total=len(SCENARIOS),
                action=str(event["action"]),
                reason=str(event["reasons"][0]),
            )
    return events


def _provisional_evidence_sha256(events: list[dict[str, Any]]) -> str:
    """Bind substantive checkpoint evidence while excluding volatile runtime fields."""
    stable_events = [
        {
            key: value
            for key, value in event.items()
            if key not in {"observed_at", "inference_latency_ms"}
        }
        for event in events
    ]
    return sha256_bytes(canonical_json({"events": stable_events}))


def _recovery_check(event: dict[str, Any], window: int) -> dict[str, Any]:
    within_warning_envelope = (
        event["action"] == "continue"
        and all(bool(value) for value in event["integrity"].values())
        and float(event["maximum_psi"]) < float(THRESHOLDS["psi_warning"])
        and float(event["telemetry_missingness"]) < float(THRESHOLDS["missing_warning"])
    )
    return {
        "window": window,
        "sample_count": int(event["sample_count"]),
        "labels_available": bool(event["labels_available"]),
        "action": str(event["action"]),
        "reasons": [str(reason) for reason in event["reasons"]],
        "maximum_psi": float(event["maximum_psi"]),
        "telemetry_missingness": float(event["telemetry_missingness"]),
        "integrity": {
            "model_matches": bool(event["integrity"]["model_matches"]),
            "policy_matches": bool(event["integrity"]["policy_matches"]),
        },
        "within_warning_envelope": within_warning_envelope,
    }


def _evaluate_recovery(
    model_dir: Path,
    baseline_path: Path,
    records: list[dict[str, Any]],
    emitter: _ProgressEmitter,
) -> dict[str, Any]:
    recovery_records = [record for record in records if record.get("scenario") == RECOVERY_SCENARIO]
    if len(recovery_records) != 250:
        raise ValueError("Recovery evidence requires exactly 250 ordered observations")
    windows = (recovery_records[:125], recovery_records[125:])
    checks: list[dict[str, Any]] = []
    check_events: list[dict[str, Any]] = []
    for number, window_records in enumerate(windows, start=1):
        emitter.emit(
            "recovery_monitoring",
            "started",
            f"Evaluating stable recovery window {number}",
            current=number - 1,
            total=2,
        )
        event = monitor_records(
            model_dir,
            baseline_path,
            window_records,
            labels_available=True,
        )
        check_events.append(event)
        check = _recovery_check(event, number)
        checks.append(check)
        emitter.emit(
            "recovery_monitoring",
            "advanced",
            f"Completed stable recovery window {number}",
            current=number,
            total=2,
            action=str(check["action"]),
            reason=str(check["reasons"][0]),
        )

    stable_window_count = sum(1 for check in checks if bool(check["within_warning_envelope"]))
    aggregate = monitor_records(
        model_dir,
        baseline_path,
        recovery_records,
        labels_available=True,
        operator_acknowledged=True,
        stable_window_count=stable_window_count,
    )
    most_severe = max(
        [str(aggregate["action"]), *(str(event["action"]) for event in check_events)],
        key=_ACTION_SEVERITY.__getitem__,
    )
    if stable_window_count != 2 and most_severe == "continue":
        most_severe = "investigate"
    if most_severe != aggregate["action"] or stable_window_count != 2:
        aggregate["action"] = most_severe
        aggregate["reasons"] = ["recovery_requirements_not_met"]
    aggregate["operator_acknowledged"] = True
    aggregate["stable_window_count"] = stable_window_count
    aggregate["recovery_checks"] = checks
    return aggregate


def _verify_prepared_artifacts(output: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    dataset_manifest = read_json(output / "data" / "dataset_manifest.json")
    if dataset_manifest.get("schema_version") not in SUPPORTED_SCHEMA_VERSIONS:
        raise ValueError("Prepared dataset has an unsupported schema version")
    files = dataset_manifest.get("files")
    if not isinstance(files, dict):
        raise ValueError("Prepared dataset manifest has no file hashes")
    for name, expected_hash in files.items():
        path = output / "data" / str(name)
        if not path.is_file() or sha256_file(path) != expected_hash:
            raise ValueError(f"Prepared dataset hash mismatch for {name}")
    model_manifest = read_json(output / "model" / "model_manifest.json")
    model_path = output / "model" / "model.json"
    if sha256_file(model_path) != model_manifest.get("model_sha256"):
        raise ValueError("Prepared model hash does not match its manifest")
    baseline = read_json(output / "baseline.json")
    if baseline.get("model_sha256") != model_manifest.get("model_sha256"):
        raise ValueError("Prepared baseline and model manifest do not match")
    return dataset_manifest, model_manifest


def prepare_guided_demo(
    output: Path,
    regenerate_zeek: bool = False,
    seed: int = DEFAULT_SEED,
    *,
    observer: ProgressObserver | None = None,
    mode: DemoMode = "guided_reviewer",
    _emitter: _ProgressEmitter | None = None,
) -> dict[str, Any]:
    """Run the genuine workflow up to the operator acknowledgement."""
    output.mkdir(parents=True, exist_ok=True)
    _clear_completion_markers(output)
    emitter = _emitter or _ProgressEmitter(observer)
    started_at = datetime.now(UTC).isoformat()
    _write_run_state(
        output,
        phase="preparing",
        mode=mode,
        regenerate_zeek=regenerate_zeek,
        seed=seed,
        emitter=emitter,
        started_at=started_at,
    )
    try:
        emitter.emit("preflight", "started", "Checking the run workspace")
        if not output.is_dir():
            raise ValueError("The demonstration output is not a directory")
        emitter.emit("preflight", "completed", "Run workspace is ready")

        data_dir = output / "data"
        model_dir = output / "model"
        emitter.emit(
            "telemetry_generation",
            "started",
            "Generating 5,000 deterministic telemetry windows and safe PCAP traffic",
            current=0,
            total=5000,
        )

        def report_generation(current: int, total: int) -> None:
            emitter.emit(
                "telemetry_generation",
                "advanced",
                f"Generated {current:,} of {total:,} windows",
                current=current,
                total=total,
            )

        manifest = generate_dataset(data_dir, seed=seed, progress=report_generation)
        emitter.emit(
            "telemetry_generation",
            "completed",
            "Telemetry, labels, authentication events, and safe PCAP are complete",
            current=5000,
            total=5000,
            artifact="data/dataset_manifest.json",
            artifact_sha256=sha256_file(data_dir / "dataset_manifest.json"),
        )

        if regenerate_zeek:
            emitter.emit(
                "zeek_processing",
                "started",
                "Processing the PCAP with the digest-pinned Zeek container",
            )
            manifest = process_with_zeek(data_dir, ZEEK_IMAGE)
            emitter.emit(
                "zeek_processing",
                "completed",
                "Pinned Zeek processing and observation rebuilding are complete",
                artifact="data/dataset_manifest.json",
                artifact_sha256=sha256_file(data_dir / "dataset_manifest.json"),
            )
        else:
            emitter.emit(
                "zeek_processing",
                "completed",
                "Portable generated Zeek-format records selected",
                artifact="data/conn.log",
                artifact_sha256=sha256_file(data_dir / "conn.log"),
            )

        emitter.emit("xgboost_training", "started", "Training the XGBoost classifier")

        def report_model(stage: str) -> None:
            if stage == "xgboost":
                emitter.emit(
                    "xgboost_training",
                    "completed",
                    "XGBoost training and calibration inference are complete",
                )
                emitter.emit(
                    "logistic_comparison",
                    "started",
                    "Training the logistic regression comparison",
                )
            else:
                emitter.emit(
                    "logistic_comparison",
                    "completed",
                    "Logistic regression comparison is complete",
                )

        model_manifest = train_model(
            data_dir / "observations.jsonl",
            model_dir,
            seed,
            progress=report_model,
        )
        emitter.emit(
            "model_manifest",
            "completed",
            "Native model and model manifest are recorded",
            artifact="model/model_manifest.json",
            artifact_sha256=sha256_file(model_dir / "model_manifest.json"),
        )

        baseline_path = output / "baseline.json"
        emitter.emit("assurance_baseline", "started", "Establishing the reference envelope")
        create_baseline(model_dir, data_dir / "observations.jsonl", baseline_path)
        emitter.emit(
            "assurance_baseline",
            "completed",
            "Reference metrics, distributions, and policy hashes are recorded",
            artifact="baseline.json",
            artifact_sha256=sha256_file(baseline_path),
        )

        records = read_jsonl(data_dir / "observations.jsonl")
        events = _evaluate_first_phase(model_dir, baseline_path, records, emitter)
        provisional_actions = {str(event["scenario"]): str(event["action"]) for event in events}
        provisional_digest = _provisional_evidence_sha256(events)
        emitter.emit(
            "operator_checkpoint",
            "awaiting_input",
            "Review the withdrawal evidence and acknowledge the investigation",
            current=5,
            total=6,
            action=str(events[-1]["action"]),
            reason=str(events[-1]["reasons"][0]),
        )
        state = _write_run_state(
            output,
            phase="awaiting_acknowledgement",
            mode=mode,
            regenerate_zeek=regenerate_zeek,
            seed=seed,
            emitter=emitter,
            started_at=started_at,
            provisional_actions=provisional_actions,
            provisional_evidence_sha256=provisional_digest,
        )
        return {
            "output": str(output),
            "state": state,
            "dataset_manifest": manifest,
            "model_manifest": model_manifest,
            "provisional_events": events,
        }
    except Exception as error:
        emitter.emit(
            "workflow",
            "failed",
            f"Demonstration preparation failed with {error.__class__.__name__}",
        )
        _write_run_state(
            output,
            phase="failed",
            mode=mode,
            regenerate_zeek=regenerate_zeek,
            seed=seed,
            emitter=emitter,
            started_at=started_at,
            error=f"{error.__class__.__name__}: {error}",
        )
        raise


def _summary(
    output: Path,
    *,
    dataset_manifest: dict[str, Any],
    model_manifest: dict[str, Any],
    events: list[dict[str, Any]],
    verification: dict[str, Any],
    evidence_bindings: dict[str, Any],
) -> dict[str, Any]:
    artifact_paths = (
        "baseline.json",
        "assurance_events.jsonl",
        "public_key.pem",
        "verification_report.json",
        "data/dataset_manifest.json",
        "model/model.json",
        "model/model_manifest.json",
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "version": evidence_bindings["version"],
        "completed_at": datetime.now(UTC).isoformat(),
        "git_revision": evidence_bindings["git_revision"],
        "python": evidence_bindings["python"],
        "seed": evidence_bindings["seed"],
        "trl_claim": evidence_bindings["trl_claim"],
        "limitations": evidence_bindings["limitations"],
        "demonstration": evidence_bindings["demonstration"],
        "dataset_manifest": dataset_manifest,
        "model_manifest": model_manifest,
        "scenario_actions": {str(event["scenario"]): str(event["action"]) for event in events},
        "ledger_valid": bool(verification["valid"]),
        "artifacts": {name: sha256_file(output / name) for name in artifact_paths},
    }


def _build_evidence_bindings(
    output: Path,
    *,
    seed: int,
    mode: DemoMode,
    regenerate_zeek: bool,
    dataset_manifest: dict[str, Any],
    events: list[dict[str, Any]],
) -> dict[str, Any]:
    """Create the provenance and artifact index protected by the terminal seal."""
    return {
        "schema_version": SCHEMA_VERSION,
        "version": __version__,
        "git_revision": _git_revision(),
        "python": platform.python_version(),
        "seed": seed,
        "trl_claim": "Evidence consistent with TRL 3 laboratory proof of concept",
        "limitations": list(_LIMITATIONS),
        "demonstration": {
            "mode": mode,
            "telemetry_source": str(dataset_manifest["zeek_mode"]),
            "zeek_validated": regenerate_zeek,
            "operator_acknowledged": True,
            "recovery_window_count": int(events[-1]["stable_window_count"]),
        },
        "artifacts": {name: sha256_file(output / name) for name in _BOUND_ARTIFACTS},
    }


def complete_guided_demo(
    output: Path,
    *,
    operator_acknowledged: bool,
    observer: ProgressObserver | None = None,
    _emitter: _ProgressEmitter | None = None,
) -> dict[str, Any]:
    """Reconstruct, gate, sign, and verify the final six-event evidence."""
    state = read_guided_state(output)
    if state.get("phase") != "awaiting_acknowledgement":
        raise ValueError("The guided run is not awaiting operator acknowledgement")
    if operator_acknowledged is not True:
        raise PermissionError("Operator acknowledgement is required before recovery")
    mode = str(state["mode"])
    if mode not in {"automatic_cli", "guided_reviewer"}:
        raise ValueError("Guided run has an unsupported demonstration mode")
    typed_mode: DemoMode = "automatic_cli" if mode == "automatic_cli" else "guided_reviewer"
    seed = int(state["seed"])
    regenerate_zeek = bool(state["regenerate_zeek"])
    started_at = str(state["started_at"])
    emitter = _emitter or _ProgressEmitter(
        observer,
        sequence=int(state["progress_sequence"]),
        elapsed_offset=float(state["elapsed_seconds"]),
    )
    _write_run_state(
        output,
        phase="finalising",
        mode=typed_mode,
        regenerate_zeek=regenerate_zeek,
        seed=seed,
        emitter=emitter,
        started_at=started_at,
        provisional_actions={str(k): str(v) for k, v in state["provisional_actions"].items()},
        provisional_evidence_sha256=str(state.get("provisional_evidence_sha256") or ""),
    )
    try:
        emitter.emit(
            "operator_checkpoint",
            "completed",
            "Investigation acknowledgement recorded for the laboratory workflow",
            current=5,
            total=6,
        )
        emitter.emit(
            "evidence_reconstruction",
            "started",
            "Rechecking prepared artifacts and reconstructing unsigned scenario results",
        )
        dataset_manifest, model_manifest = _verify_prepared_artifacts(output)
        model_dir = output / "model"
        baseline_path = output / "baseline.json"
        records = read_jsonl(output / "data" / "observations.jsonl")
        events = _evaluate_first_phase(model_dir, baseline_path, records)
        reconstructed_actions = {str(event["scenario"]): str(event["action"]) for event in events}
        expected_actions = {str(k): str(v) for k, v in state["provisional_actions"].items()}
        expected_digest = state.get("provisional_evidence_sha256")
        if (
            not isinstance(expected_digest, str)
            or len(expected_digest) != 64
            or reconstructed_actions != expected_actions
            or _provisional_evidence_sha256(events) != expected_digest
        ):
            raise ValueError(
                "Reconstructed first-phase evidence does not match the acknowledged checkpoint"
            )
        emitter.emit(
            "evidence_reconstruction",
            "completed",
            "Prepared artifacts and the first five scenario results were reconstructed",
        )

        recovery = _evaluate_recovery(model_dir, baseline_path, records, emitter)
        events.append(recovery)
        emitter.emit(
            "scenario_monitoring",
            "completed",
            "All six assurance scenarios are complete",
            current=6,
            total=6,
            action=str(recovery["action"]),
            reason=str(recovery["reasons"][0]),
        )

        ledger_path = output / "assurance_events.jsonl"
        public_key_path = output / "public_key.pem"
        evidence_bindings = _build_evidence_bindings(
            output,
            seed=seed,
            mode=typed_mode,
            regenerate_zeek=regenerate_zeek,
            dataset_manifest=dataset_manifest,
            events=events,
        )
        emitter.emit("ledger_signing", "started", "Signing the six-event SHA-256 hash chain")
        sign_events(
            events,
            ledger_path,
            public_key_path,
            evidence_bindings=evidence_bindings,
        )
        emitter.emit(
            "ledger_signing",
            "completed",
            "Signed ledger and public verification key are recorded",
            artifact="assurance_events.jsonl",
            artifact_sha256=sha256_file(ledger_path),
        )

        emitter.emit(
            "ledger_verification",
            "started",
            "Verifying event order, hashes, and signatures",
        )
        verification = write_verification_report(
            ledger_path,
            public_key_path,
            output / "verification_report.json",
        )
        if verification["valid"] is not True:
            raise RuntimeError(f"Final ledger verification failed, {verification['error']}")
        emitter.emit(
            "ledger_verification",
            "completed",
            "The six-event ledger and terminal seal are valid",
            artifact="verification_report.json",
            artifact_sha256=sha256_file(output / "verification_report.json"),
        )

        emitter.emit("evidence_preparation", "started", "Preparing the verified evidence index")
        summary = _summary(
            output,
            dataset_manifest=dataset_manifest,
            model_manifest=model_manifest,
            events=events,
            verification=verification,
            evidence_bindings=evidence_bindings,
        )
        write_json(output / "run_summary.json", summary)
        emitter.emit(
            "evidence_preparation",
            "completed",
            "Verified reviewer evidence is ready",
            artifact="run_summary.json",
            artifact_sha256=sha256_file(output / "run_summary.json"),
        )
        _write_run_state(
            output,
            phase="completed",
            mode=typed_mode,
            regenerate_zeek=regenerate_zeek,
            seed=seed,
            emitter=emitter,
            started_at=started_at,
            provisional_actions={str(event["scenario"]): str(event["action"]) for event in events},
            provisional_evidence_sha256=str(state["provisional_evidence_sha256"]),
        )
        return summary
    except Exception as error:
        emitter.emit(
            "workflow",
            "failed",
            f"Demonstration finalisation failed with {error.__class__.__name__}",
        )
        _write_run_state(
            output,
            phase="failed",
            mode=typed_mode,
            regenerate_zeek=regenerate_zeek,
            seed=seed,
            emitter=emitter,
            started_at=started_at,
            provisional_actions={str(k): str(v) for k, v in state["provisional_actions"].items()},
            provisional_evidence_sha256=str(state.get("provisional_evidence_sha256") or ""),
            error=f"{error.__class__.__name__}: {error}",
        )
        raise


def run_demo(
    output: Path,
    regenerate_zeek: bool = False,
    seed: int = DEFAULT_SEED,
    *,
    observer: ProgressObserver | None = None,
) -> dict[str, Any]:
    """Run the complete automatic laboratory demonstration."""
    emitter = _ProgressEmitter(observer)
    prepare_guided_demo(
        output,
        regenerate_zeek=regenerate_zeek,
        seed=seed,
        mode="automatic_cli",
        _emitter=emitter,
    )
    return complete_guided_demo(
        output,
        operator_acknowledged=True,
        _emitter=emitter,
    )
