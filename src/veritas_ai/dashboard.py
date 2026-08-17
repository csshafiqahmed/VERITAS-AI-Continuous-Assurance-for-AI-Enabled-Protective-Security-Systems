"""Read-only Streamlit dashboard for completed evidence runs."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import streamlit as st


def load_run(run_dir: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    summary = json.loads((run_dir / "run_summary.json").read_text(encoding="utf-8"))
    events = [
        json.loads(line)["event"]
        for line in (run_dir / "assurance_events.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    return summary, events


def render(run_dir: Path) -> None:
    summary, events = load_run(run_dir)
    st.set_page_config(page_title="VERITAS-AI", layout="wide")
    st.title("VERITAS-AI assurance evidence")
    st.warning("Laboratory evidence only. This release does not demonstrate TRL 6.")
    left, middle, right = st.columns(3)
    left.metric("Version", str(summary["version"]))
    middle.metric("Ledger valid", str(summary["ledger_valid"]))
    right.metric("Scenarios", len(events))
    st.subheader("Scenario decisions")
    st.dataframe(
        [
            {
                "scenario": event["scenario"],
                "action": event["action"],
                "maximum PSI": event["maximum_psi"],
                "missingness": event["telemetry_missingness"],
                "labels": event["labels_available"],
                "reason": ", ".join(event["reasons"]),
            }
            for event in events
        ],
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
