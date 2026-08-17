"""Read-only Streamlit dashboard for completed evidence runs."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import streamlit as st

from veritas_ai.io import read_json, read_jsonl
from veritas_ai.ledger import verify_ledger


def dashboard_snapshot(run_dir: Path) -> dict[str, Any]:
    """Build display values from a verified ledger and its machine-readable summary."""
    summary = read_json(run_dir / "run_summary.json")
    verification = verify_ledger(
        run_dir / "assurance_events.jsonl",
        run_dir / "public_key.pem",
    )
    if not verification["valid"]:
        raise ValueError(f"Dashboard refused an invalid evidence ledger, {verification['error']}")

    events: list[dict[str, Any]] = []
    for index, record in enumerate(read_jsonl(run_dir / "assurance_events.jsonl"), start=1):
        if record.get("record_type") == "seal":
            continue
        event = record.get("event")
        if not isinstance(event, dict):
            raise ValueError(f"Ledger record {index} does not contain an event object")
        events.append(event)
    if len(events) != verification["events_checked"]:
        raise ValueError("Verified event count does not match the dashboard event count")

    scenario_actions = {str(event["scenario"]): str(event["action"]) for event in events}
    if summary.get("scenario_actions") != scenario_actions:
        raise ValueError("Run summary decisions do not match the signed ledger")
    if summary.get("ledger_valid") is not True:
        raise ValueError("Run summary does not record a valid ledger")

    rows = [
        {
            "scenario": event["scenario"],
            "action": event["action"],
            "maximum PSI": event["maximum_psi"],
            "missingness": event["telemetry_missingness"],
            "labels": event["labels_available"],
            "reason": ", ".join(event["reasons"]),
        }
        for event in events
    ]
    return {
        "version": summary["version"],
        "ledger_valid": verification["valid"],
        "scenario_count": len(events),
        "scenario_actions": scenario_actions,
        "rows": rows,
        "events": events,
    }


def render(run_dir: Path) -> None:
    snapshot = dashboard_snapshot(run_dir)
    events = snapshot["events"]
    st.set_page_config(page_title="VERITAS-AI", layout="wide")
    st.title("VERITAS-AI assurance evidence")
    st.warning("Laboratory evidence only. This release does not demonstrate TRL 6.")
    left, middle, right = st.columns(3)
    left.metric("Version", str(snapshot["version"]))
    middle.metric("Ledger valid", str(snapshot["ledger_valid"]))
    right.metric("Scenarios", int(snapshot["scenario_count"]))
    st.subheader("Scenario decisions")
    st.dataframe(
        snapshot["rows"],
        use_container_width=True,
        hide_index=True,
    )
    selected = st.selectbox("Inspect scenario", [str(event["scenario"]) for event in events])
    event = next(item for item in events if item["scenario"] == selected)
    st.json(event)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit("A completed run directory is required")
    render(Path(sys.argv[1]))
