"""Two-mode Streamlit application for guided runs and signed evidence review."""

from __future__ import annotations

import argparse
import hashlib
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import streamlit as st

from veritas_ai.constants import CLASSES, DEFAULT_SEED, FEATURES, THRESHOLDS, ZEEK_IMAGE
from veritas_ai.io import read_json
from veritas_ai.reviewer import (
    build_reviewer_archive,
    create_reviewer_run,
    discover_completed_runs,
    load_verified_run,
    reviewer_preflight,
    safe_tamper_test,
)
from veritas_ai.workflow import (
    ProgressEvent,
    complete_guided_demo,
    prepare_guided_demo,
    read_guided_state,
)

GUIDED_MODE = "Guided Demonstration"
EVIDENCE_MODE = "Signed Evidence Review"
_ACTION_DISPLAY = {
    "continue": "✓ Continue",
    "investigate": "⚠ Investigate",
    "recalibrate": "↻ Recalibrate",
    "withdraw": "✕ Withdraw",
}
_SCENARIO_DISPLAY = {
    "stable_operation": "Stable operation",
    "benign_workload_change": "Benign workload change",
    "partial_telemetry_loss": "Partial telemetry loss",
    "gradual_feature_drift": "Gradual feature drift",
    "model_replacement": "Model replacement",
    "recovery_after_investigation": "Recovery after investigation",
}
_REASON_DISPLAY = {
    "inside_reference_envelope": "Inside the reference envelope",
    "approved_context_change": "Approved benign context change",
    "partial_telemetry_loss": "Partial telemetry loss",
    "persistent_labelled_deterioration": "Persistent labelled deterioration",
    "model_or_policy_integrity_mismatch": "Model or policy integrity mismatch",
    "acknowledged_recovery_with_two_stable_windows": ("Two stable windows after acknowledgement"),
    "recovery_requirements_not_met": "Recovery requirements not met",
}
_MODE_DISPLAY = {
    "guided_reviewer": "Guided",
    "automatic_cli": "Automatic",
    "completed_evidence": "Completed",
}
_TELEMETRY_DISPLAY = {
    "synthetic_zeek_compatible": "Portable",
    "docker_zeek": "Zeek",
}
_STAGE_PROGRESS = {
    "preflight": (0.00, 0.02),
    "telemetry_generation": (0.02, 0.45),
    "zeek_processing": (0.45, 0.52),
    "xgboost_training": (0.52, 0.60),
    "logistic_comparison": (0.60, 0.64),
    "model_manifest": (0.64, 0.66),
    "assurance_baseline": (0.66, 0.72),
    "scenario_monitoring": (0.72, 0.86),
    "operator_checkpoint": (0.86, 0.87),
    "evidence_reconstruction": (0.87, 0.89),
    "recovery_monitoring": (0.89, 0.94),
    "ledger_signing": (0.94, 0.97),
    "ledger_verification": (0.97, 0.99),
    "evidence_preparation": (0.99, 1.00),
    "workflow": (0.00, 1.00),
}


@dataclass(frozen=True, slots=True)
class DashboardConfig:
    runs_root: Path
    run: Path | None = None


class ActiveRunRegistry:
    """Coordinate one active reviewer run inside a Streamlit process."""

    def __init__(self, stale_after_seconds: float = 1800.0) -> None:
        self._lock = threading.Lock()
        self._active_run: str | None = None
        self._claimed_at = 0.0
        self._stale_after_seconds = stale_after_seconds

    def _expire_locked(self) -> None:
        if (
            self._active_run is not None
            and time.monotonic() - self._claimed_at > self._stale_after_seconds
        ):
            self._active_run = None
            self._claimed_at = 0.0

    def claim(self, run_dir: Path) -> bool:
        value = str(run_dir.resolve(strict=False))
        with self._lock:
            self._expire_locked()
            if self._active_run not in {None, value}:
                return False
            self._active_run = value
            self._claimed_at = time.monotonic()
            return True

    def release(self, run_dir: Path) -> None:
        value = str(run_dir.resolve(strict=False))
        with self._lock:
            if self._active_run == value:
                self._active_run = None
                self._claimed_at = 0.0

    def another_active(self, run_dir: Path | None = None) -> bool:
        value = str(run_dir.resolve(strict=False)) if run_dir is not None else None
        with self._lock:
            self._expire_locked()
            return self._active_run is not None and self._active_run != value


@st.cache_resource
def _run_registry() -> ActiveRunRegistry:
    return ActiveRunRegistry()


def _parse_config(arguments: list[str]) -> DashboardConfig:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--run", type=Path)
    parser.add_argument("--runs-root", type=Path, default=Path("runs/reviewer"))
    values, _ = parser.parse_known_args(arguments)
    return DashboardConfig(runs_root=values.runs_root, run=values.run)


def dashboard_snapshot(run_dir: Path) -> dict[str, Any]:
    """Build display values only from a reconciled signed run."""
    verified = load_verified_run(run_dir)
    summary = verified["summary"]
    events = verified["events"]
    rows = [
        {
            "scenario": _SCENARIO_DISPLAY.get(str(event["scenario"]), str(event["scenario"])),
            "action": str(event["action"]),
            "outcome": _ACTION_DISPLAY.get(str(event["action"]), str(event["action"])),
            "maximum PSI": float(event.get("maximum_psi", 0.0)),
            "missingness": float(event.get("telemetry_missingness", 0.0)),
            "labels": bool(event.get("labels_available", False)),
            "reason": _display_reasons(event.get("reasons", [])),
        }
        for event in events
    ]
    dataset_manifest = summary.get("dataset_manifest", {})
    demonstration = summary.get("demonstration")
    if not isinstance(demonstration, dict):
        demonstration = {
            "mode": "completed_evidence",
            "telemetry_source": dataset_manifest.get("zeek_mode", "not recorded"),
            "zeek_validated": dataset_manifest.get("zeek_mode") == "docker_zeek",
            "operator_acknowledged": False,
            "recovery_window_count": 0,
        }
    return {
        "run_dir": verified["run_dir"],
        "version": summary["version"],
        "schema_version": summary.get("schema_version", "1.0"),
        "ledger_schema_version": verified["verification"].get("ledger_schema_version"),
        "ledger_valid": verified["verification"]["valid"],
        "scenario_count": len(events),
        "scenario_actions": verified["scenario_actions"],
        "rows": rows,
        "events": events,
        "summary": summary,
        "demonstration": demonstration,
        "model_manifest": summary.get("model_manifest", {}),
        "artifacts": summary.get("artifacts", {}),
        "verification": verified["verification"],
        "baseline": read_json(Path(verified["run_dir"]) / "baseline.json"),
    }


def _display_reasons(reasons: Any) -> str:
    if not isinstance(reasons, list):
        return "Not recorded"
    return ", ".join(_REASON_DISPLAY.get(str(reason), str(reason)) for reason in reasons)


def _scenario_table(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "Scenario": row["scenario"],
            "Outcome": row["outcome"],
            "Maximum PSI": row["maximum PSI"],
            "Missingness": row["missingness"],
            "Ground truth": "Available" if row["labels"] else "Unavailable",
        }
        for row in rows
    ]


def _progress_fraction(event: ProgressEvent) -> float:
    start, end = _STAGE_PROGRESS[event.stage]
    if event.current is not None and event.total:
        fraction = event.current / event.total
    elif event.state == "completed":
        fraction = 1.0
    else:
        fraction = 0.0
    return min(1.0, max(0.0, start + (end - start) * fraction))


class _LiveProgress:
    def __init__(self, title: str) -> None:
        self.events: list[dict[str, Any]] = []
        self.status = st.status(title, expanded=True)
        self.bar = st.progress(0.0, text="Waiting for the first completed stage")
        columns = st.columns(3)
        self.stage_metric = columns[0].empty()
        self.elapsed_metric = columns[1].empty()
        self.action_metric = columns[2].empty()

    def observe(self, event: ProgressEvent) -> None:
        self.events.append(event.as_dict())
        self.bar.progress(_progress_fraction(event), text=event.message)
        self.status.write(f"{event.sequence}. {event.message}")
        self.stage_metric.metric("Current stage", event.stage.replace("_", " ").title())
        self.elapsed_metric.metric("Elapsed", f"{event.elapsed_seconds:.1f} seconds")
        self.action_metric.metric(
            "Latest outcome",
            _ACTION_DISPLAY.get(event.action or "", event.action or "Not yet available"),
        )
        if event.state == "failed":
            self.status.update(label=event.message, state="error", expanded=True)
        elif event.state == "awaiting_input":
            self.status.update(label=event.message, state="running", expanded=True)
        elif event.stage == "evidence_preparation" and event.state == "completed":
            self.status.update(label=event.message, state="complete", expanded=False)


def _pending_runs(runs_root: Path) -> list[Path]:
    try:
        candidates = sorted(runs_root.resolve(strict=True).iterdir(), reverse=True)
    except FileNotFoundError:
        return []
    pending: list[Path] = []
    for candidate in candidates:
        if not candidate.is_dir() or candidate.is_symlink():
            continue
        try:
            state = read_guided_state(candidate)
        except (OSError, KeyError, TypeError, ValueError):
            continue
        if state.get("phase") == "awaiting_acknowledgement":
            pending.append(candidate)
    return pending


def _provisional_rows(actions: dict[str, Any]) -> list[dict[str, str]]:
    return [
        {
            "scenario": _SCENARIO_DISPLAY.get(str(scenario), str(scenario)),
            "live outcome": _ACTION_DISPLAY.get(str(action), str(action)),
        }
        for scenario, action in actions.items()
    ]


def _clear_guided_session() -> None:
    for key in (
        "reviewer_run_dir",
        "reviewer_progress",
        "reviewer_selected_run",
        "reviewer_provisional_events",
    ):
        st.session_state.pop(key, None)


def _open_evidence(run_dir: str) -> None:
    st.session_state["reviewer_mode"] = EVIDENCE_MODE
    st.session_state["reviewer_selected_run"] = run_dir


def _render_checkpoint(run_dir: Path, registry: ActiveRunRegistry) -> None:
    state = read_guided_state(run_dir)
    st.header("Operator recovery checkpoint")
    st.warning(
        "The observed model hash does not match the approved baseline. "
        "The current advisory outcome is Withdraw."
    )
    st.caption(
        "These are live provisional results. The final stage reconstructs the events from "
        "the prepared artifacts before signing them."
    )
    st.dataframe(
        _provisional_rows(state.get("provisional_actions", {})),
        width="stretch",
        hide_index=True,
    )
    st.caption(
        "Selecting Acknowledge Investigation records a demonstration workflow step and begins "
        "the two recovery checks. It is not a legal signature or a statement of operator identity."
    )
    if st.button(
        "Acknowledge Investigation",
        type="primary",
        width="stretch",
    ):
        view = _LiveProgress("Reconstructing and signing the assurance evidence")
        try:
            complete_guided_demo(
                run_dir,
                operator_acknowledged=True,
                observer=view.observe,
            )
        except Exception as error:
            registry.release(run_dir)
            st.error(f"The guided demonstration could not be completed. {error}")
        else:
            registry.release(run_dir)
            st.session_state["reviewer_progress"] = view.events
            st.session_state["reviewer_selected_run"] = str(run_dir)
            st.rerun()


def _render_completed_guided(run_dir: Path, registry: ActiveRunRegistry) -> None:
    snapshot = dashboard_snapshot(run_dir)
    st.success("The signed six-event evidence ledger is valid and ready for review.")
    columns = st.columns(3)
    columns[0].metric("Scenarios", snapshot["scenario_count"])
    columns[1].metric("Ledger", "Valid")
    columns[2].metric("Stable recovery windows", snapshot["demonstration"]["recovery_window_count"])
    st.dataframe(snapshot["rows"], width="stretch", hide_index=True)
    left, right = st.columns(2)
    left.button(
        "Open Signed Evidence Review",
        type="primary",
        width="stretch",
        on_click=_open_evidence,
        args=(str(run_dir),),
    )
    if right.button("Start a new demonstration", width="stretch"):
        registry.release(run_dir)
        _clear_guided_session()
        st.rerun()


def _render_guided(runs_root: Path, registry: ActiveRunRegistry) -> None:
    st.title("VERITAS-AI Guided Reviewer Demonstration")
    st.warning(
        "Laboratory evidence only. This demonstration is consistent with TRL 3 and does "
        "not demonstrate TRL 6 or operational effectiveness."
    )
    st.write(
        "Run the actual telemetry, training, baselining, monitoring, recovery, signing, and "
        "verification workflow. No automatic retraining or traffic blocking occurs."
    )

    current_value = st.session_state.get("reviewer_run_dir")
    current_run = Path(str(current_value)) if current_value else None
    if current_run is None:
        pending = _pending_runs(runs_root)
        if pending:
            pending_run = st.selectbox(
                "Resume a run awaiting acknowledgement",
                pending,
                format_func=lambda path: path.name,
            )
            if st.button("Resume pending checkpoint", width="stretch"):
                if registry.claim(pending_run):
                    st.session_state["reviewer_run_dir"] = str(pending_run)
                    st.rerun()
                else:
                    st.error("Another reviewer run is active in this application process.")

    if current_run is not None:
        try:
            state = read_guided_state(current_run)
        except (OSError, KeyError, TypeError, ValueError) as error:
            registry.release(current_run)
            st.error(f"The local run state cannot be read. {error}")
        else:
            phase = state.get("phase")
            st.caption(f"Run {current_run.name}")
            if phase == "awaiting_acknowledgement":
                registry.claim(current_run)
                _render_checkpoint(current_run, registry)
                return
            if phase == "completed":
                registry.release(current_run)
                _render_completed_guided(current_run, registry)
                return
            if phase == "failed":
                registry.release(current_run)
                st.error(f"This run failed. {state.get('error') or 'No diagnostic was recorded.'}")
                if st.button("Start a new demonstration", width="stretch"):
                    _clear_guided_session()
                    st.rerun()
                return
            st.info(f"The current local phase is {phase}.")
            return

    st.header("Demonstration setup")
    st.metric("Deterministic seed", DEFAULT_SEED)
    use_zeek = st.toggle(
        "Validate the generated PCAP through the pinned Zeek container",
        value=False,
        help=f"Optional route using {ZEEK_IMAGE}",
    )
    preflight = reviewer_preflight(
        runs_root,
        require_zeek=use_zeek,
        another_run_active=registry.another_active(),
    )
    status_icon = {"pass": "✓", "warning": "⚠", "fail": "✕"}
    st.dataframe(
        [
            {
                "status": f"{status_icon[check['status']]} {check['status'].title()}",
                "check": check["name"],
                "detail": check["detail"],
            }
            for check in preflight.rows()
        ],
        width="stretch",
        hide_index=True,
    )
    if st.button(
        "Start New Demonstration",
        type="primary",
        disabled=not preflight.ready,
        width="stretch",
    ):
        run_dir = create_reviewer_run(runs_root)
        if not registry.claim(run_dir):
            st.error("Another reviewer run became active. Please retry after it completes.")
            return
        st.session_state["reviewer_run_dir"] = str(run_dir)
        view = _LiveProgress("Running the live laboratory pipeline")
        try:
            prepared = prepare_guided_demo(
                run_dir,
                regenerate_zeek=use_zeek,
                observer=view.observe,
            )
        except Exception as error:
            registry.release(run_dir)
            st.error(f"The guided demonstration could not reach the checkpoint. {error}")
        else:
            st.session_state["reviewer_progress"] = view.events
            st.session_state["reviewer_provisional_events"] = prepared["provisional_events"]
            st.rerun()


def _render_threshold_charts(events: list[dict[str, Any]]) -> None:
    psi_rows = [
        {
            "Scenario": _SCENARIO_DISPLAY.get(str(event["scenario"]), str(event["scenario"])),
            "Observed PSI": float(event.get("maximum_psi", 0.0)),
            "Warning": float(THRESHOLDS["psi_warning"]),
            "Critical": float(THRESHOLDS["psi_critical"]),
        }
        for event in events
    ]
    missing_rows = [
        {
            "Scenario": _SCENARIO_DISPLAY.get(str(event["scenario"]), str(event["scenario"])),
            "Observed missingness": float(event.get("telemetry_missingness", 0.0)),
            "Warning": float(THRESHOLDS["missing_warning"]),
            "Critical": float(THRESHOLDS["missing_critical"]),
        }
        for event in events
    ]
    left, right = st.columns(2)
    with left:
        st.subheader("Population Stability Index")
        st.bar_chart(
            psi_rows,
            x="Scenario",
            y=["Observed PSI", "Warning", "Critical"],
            width="stretch",
        )
    with right:
        st.subheader("Telemetry missingness")
        st.bar_chart(
            missing_rows,
            x="Scenario",
            y=["Observed missingness", "Warning", "Critical"],
            width="stretch",
        )


def _render_selected_event(event: dict[str, Any], model_manifest: dict[str, Any]) -> None:
    action = str(event["action"])
    action_message = _ACTION_DISPLAY.get(action, action)
    if action == "continue":
        st.success(action_message)
    elif action == "investigate":
        st.warning(action_message)
    elif action == "recalibrate":
        st.info(action_message)
    else:
        st.error(action_message)
    st.write(f"Reason  {_display_reasons(event.get('reasons', []))}")

    metrics = st.columns(4)
    metrics[0].metric("Samples", int(event.get("sample_count", 0)))
    metrics[1].metric("Maximum PSI", f"{float(event.get('maximum_psi', 0.0)):.3f}")
    metrics[2].metric("Missingness", f"{100 * float(event.get('telemetry_missingness', 0.0)):.1f}%")
    metrics[3].metric(
        "Inference latency",
        f"{float(event.get('inference_latency_ms', 0.0)):.2f} ms",
    )

    if bool(event.get("labels_available")):
        st.success("Ground truth is available for this offline laboratory window.")
        labelled = event.get("labelled_metrics")
        if isinstance(labelled, dict):
            labelled_columns = st.columns(3)
            labelled_columns[0].metric("Macro F1", f"{float(labelled['macro_f1']):.3f}")
            labelled_columns[1].metric(
                "Expected calibration error",
                f"{float(labelled['expected_calibration_error']):.3f}",
            )
            maximum_fnr = event.get("maximum_fnr_increase")
            labelled_columns[2].metric(
                "Maximum FNR increase",
                "Unavailable" if maximum_fnr is None else f"{100 * float(maximum_fnr):.1f} points",
            )
            matrix = labelled.get("confusion_matrix")
            classes = model_manifest.get("classes", CLASSES)
            if isinstance(matrix, list) and len(matrix) == len(classes):
                st.subheader("Confusion matrix")
                st.dataframe(
                    [
                        {
                            "Actual class": classes[row_index],
                            **{
                                f"Predicted {classes[column_index]}": value
                                for column_index, value in enumerate(row)
                            },
                        }
                        for row_index, row in enumerate(matrix)
                    ],
                    width="stretch",
                    hide_index=True,
                )
    else:
        st.info(
            "Ground truth is unavailable. Current accuracy, calibration, and false-negative "
            "performance are not claimed for this window."
        )
        st.metric(
            "Confidence CUSUM",
            f"{float(event.get('confidence_cusum_sigma', 0.0)):.2f} standard deviations",
        )

    feature_psi = event.get("feature_psi")
    if isinstance(feature_psi, dict):
        st.subheader("Feature-level distribution change")
        feature_rows: list[dict[str, str | float]] = [
            {"Feature": name, "PSI": float(feature_psi.get(name, 0.0))} for name in FEATURES
        ]
        feature_rows.sort(key=lambda row: float(row["PSI"]), reverse=True)
        st.bar_chart(feature_rows, x="Feature", y="PSI", width="stretch")

    recovery_checks = event.get("recovery_checks")
    if isinstance(recovery_checks, list):
        st.subheader("Signed recovery checks")
        st.dataframe(
            [
                {
                    "window": check["window"],
                    "samples": check["sample_count"],
                    "outcome": _ACTION_DISPLAY.get(str(check["action"]), str(check["action"])),
                    "maximum PSI": check["maximum_psi"],
                    "missingness": check["telemetry_missingness"],
                    "integrity": all(bool(value) for value in check["integrity"].values()),
                    "inside warning envelope": check["within_warning_envelope"],
                }
                for check in recovery_checks
            ],
            width="stretch",
            hide_index=True,
        )

    with st.expander("Inspect the raw signed event"):
        st.json(event)


def _download_controls(snapshot: dict[str, Any]) -> None:
    run_dir = Path(snapshot["run_dir"])
    cache_key = f"reviewer_archives_{sha256_path(run_dir)}"
    cached = st.session_state.setdefault(cache_key, {})
    left, right = st.columns(2)
    if left.button("Prepare Compact Evidence Bundle", width="stretch"):
        try:
            cached["compact"] = build_reviewer_archive(run_dir, full=False)
        except (OSError, ValueError) as error:
            left.error(f"Compact evidence preparation failed. {error}")
    if right.button("Create Full Run Archive", width="stretch"):
        try:
            cached["full"] = build_reviewer_archive(run_dir, full=True)
        except (OSError, ValueError) as error:
            right.error(f"Full evidence preparation failed. {error}")
    if "compact" in cached:
        left.download_button(
            "Download compact evidence",
            data=cached["compact"],
            file_name=f"veritas-ai-{run_dir.name}-compact.tar.gz",
            mime="application/gzip",
            width="stretch",
        )
    if "full" in cached:
        right.download_button(
            "Download full run",
            data=cached["full"],
            file_name=f"veritas-ai-{run_dir.name}-full.tar.gz",
            mime="application/gzip",
            width="stretch",
        )


def sha256_path(path: Path) -> str:
    return hashlib.sha256(str(path.resolve(strict=False)).encode("utf-8")).hexdigest()[:16]


def _tamper_control(snapshot: dict[str, Any]) -> None:
    run_dir = Path(snapshot["run_dir"])
    key = f"reviewer_tamper_{sha256_path(run_dir)}"
    if st.button("Run Safe Tamper Test", width="stretch"):
        try:
            st.session_state[key] = safe_tamper_test(run_dir)
        except (OSError, ValueError) as error:
            st.error(f"The safe tamper test could not run. {error}")
    result = st.session_state.get(key)
    if isinstance(result, dict):
        if (
            result["canonical_valid"]
            and result["canonical_unchanged"]
            and not result["tampered_valid"]
        ):
            st.success("The canonical ledger remains valid and the altered copy was rejected.")
        else:
            st.error("The tamper test did not satisfy its required security conditions.")
        st.dataframe(
            [
                {
                    "check": "Canonical ledger valid",
                    "result": "Pass" if result["canonical_valid"] else "Fail",
                },
                {
                    "check": "Canonical hash unchanged",
                    "result": "Pass" if result["canonical_unchanged"] else "Fail",
                },
                {
                    "check": "Tampered copy rejected",
                    "result": "Pass" if not result["tampered_valid"] else "Fail",
                },
                {"check": "Verification error", "result": str(result["tampered_error"])},
            ],
            width="stretch",
            hide_index=True,
        )


def _render_evidence(run_dir: Path) -> None:
    snapshot = dashboard_snapshot(run_dir)
    summary = snapshot["summary"]
    demonstration = snapshot["demonstration"]
    events = snapshot["events"]
    st.title("VERITAS-AI Signed Evidence Review")
    st.warning(
        "Laboratory evidence only. This release does not demonstrate TRL 6 or operational "
        "effectiveness."
    )
    first = st.columns(4)
    first[0].metric("Software version", snapshot["version"])
    first[1].metric("Evidence schema", snapshot["schema_version"])
    first[2].metric("Ledger", "Valid" if snapshot["ledger_valid"] else "Invalid")
    first[3].metric("Signed scenarios", snapshot["scenario_count"])
    second = st.columns(3)
    second[0].metric("Seed", summary.get("seed", "Not recorded"))
    mode = str(demonstration["mode"])
    second[1].metric("Mode", _MODE_DISPLAY.get(mode, mode.replace("_", " ").title()))
    telemetry_source = str(demonstration["telemetry_source"])
    second[2].metric(
        "Telemetry source",
        _TELEMETRY_DISPLAY.get(
            telemetry_source,
            telemetry_source.replace("_", " ").title(),
        ),
    )
    st.caption(
        "Zeek validation completed through the digest-pinned container."
        if demonstration["zeek_validated"]
        else (
            "Portable generated Zeek-format records were used. The Docker-backed Zeek "
            "route was not selected."
        )
    )

    st.header("Signed scenario decisions")
    st.dataframe(_scenario_table(snapshot["rows"]), width="stretch", hide_index=True)
    st.caption("Select a signed scenario below to inspect its reason and supporting evidence.")
    st.header("Threshold evidence")
    _render_threshold_charts(events)

    st.header("Selected scenario evidence")
    selected_name = st.selectbox(
        "Inspect a signed scenario",
        [str(event["scenario"]) for event in events],
        format_func=lambda value: _SCENARIO_DISPLAY.get(value, value),
    )
    selected_event = next(event for event in events if event["scenario"] == selected_name)
    _render_selected_event(selected_event, snapshot["model_manifest"])

    st.header("Integrity and provenance")
    model_manifest = snapshot["model_manifest"]
    provenance = [
        {"field": "Git revision", "value": summary.get("git_revision", "Not recorded")},
        {"field": "Model SHA-256", "value": model_manifest.get("model_sha256", "Not recorded")},
        {
            "field": "Policy SHA-256",
            "value": snapshot["baseline"].get("policy_sha256", "Not recorded"),
        },
        {
            "field": "Ledger SHA-256",
            "value": snapshot["verification"].get("ledger_sha256", "Not recorded"),
        },
    ]
    st.dataframe(provenance, width="stretch", hide_index=True)
    if snapshot["artifacts"]:
        with st.expander("Artifact hashes"):
            st.dataframe(
                [
                    {"artifact": name, "SHA-256": digest}
                    for name, digest in snapshot["artifacts"].items()
                ],
                width="stretch",
                hide_index=True,
            )

    st.header("Portable evidence")
    _download_controls(snapshot)
    st.header("Cryptographic negative test")
    _tamper_control(snapshot)


def _evidence_candidates(config: DashboardConfig) -> list[Path]:
    candidates: list[Path] = []
    if config.run is not None:
        candidates.append(config.run.resolve(strict=False))
    for path in discover_completed_runs(config.runs_root):
        resolved = path.resolve(strict=False)
        if resolved not in candidates:
            candidates.append(resolved)
    return candidates


def _render_evidence_selector(config: DashboardConfig) -> None:
    candidates = _evidence_candidates(config)
    if not candidates:
        st.title("VERITAS-AI Signed Evidence Review")
        st.info("No completed verified reviewer run is available yet.")
        return
    selected_value = st.session_state.get("reviewer_selected_run")
    default_index = 0
    if selected_value is not None:
        for index, candidate in enumerate(candidates):
            if str(candidate) == str(selected_value):
                default_index = index
                break
    selected = st.selectbox(
        "Completed evidence run",
        candidates,
        index=default_index,
        format_func=lambda path: path.name,
    )
    st.session_state["reviewer_selected_run"] = str(selected)
    try:
        _render_evidence(selected)
    except (OSError, KeyError, TypeError, ValueError) as error:
        st.error(f"Signed evidence could not be opened. {error}")


def render_application(config: DashboardConfig) -> None:
    st.set_page_config(page_title="VERITAS-AI Reviewer Demonstration", layout="wide")
    if "reviewer_mode" not in st.session_state:
        st.session_state["reviewer_mode"] = EVIDENCE_MODE if config.run else GUIDED_MODE
    mode = st.sidebar.radio(
        "Reviewer mode",
        [GUIDED_MODE, EVIDENCE_MODE],
        key="reviewer_mode",
    )
    st.sidebar.caption("VERITAS-AI v0.2.0")
    st.sidebar.warning("TRL 3 laboratory evidence only")
    if mode == GUIDED_MODE:
        _render_guided(config.runs_root, _run_registry())
    else:
        _render_evidence_selector(config)


def render(run_dir: Path) -> None:
    """Preserve the direct completed-run rendering entry point."""
    render_application(DashboardConfig(runs_root=run_dir.parent / "reviewer", run=run_dir))


if __name__ == "__main__":
    render_application(_parse_config(sys.argv[1:]))
