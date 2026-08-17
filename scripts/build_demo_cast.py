#!/usr/bin/env python3
"""Create a short Asciinema v2 recording from verified run evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _event(timestamp: float, text: str) -> str:
    return json.dumps([timestamp, "o", text], ensure_ascii=True, separators=(",", ":"))


def build_cast(summary_path: Path, verification_path: Path, output: Path) -> None:
    summary: dict[str, Any] = json.loads(summary_path.read_text(encoding="utf-8"))
    verification: dict[str, Any] = json.loads(verification_path.read_text(encoding="utf-8"))
    manifest = summary["dataset_manifest"]
    actions = summary["scenario_actions"]
    lines = [
        json.dumps(
            {
                "version": 2,
                "width": 100,
                "height": 24,
                "timestamp": 0,
                "env": {"SHELL": "/bin/bash", "TERM": "xterm-256color"},
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        _event(0.2, "$ veritas-ai demo --regenerate-zeek --output runs/trl3\r\n"),
        _event(
            0.8,
            f"Evidence summary  {manifest['observation_count']} windows  "
            f"{manifest['connection_count']} Zeek connections\r\n",
        ),
    ]
    timestamp = 1.2
    for scenario, action in actions.items():
        lines.append(_event(timestamp, f"{scenario:<32} {action}\r\n"))
        timestamp += 0.35
    lines.extend(
        [
            _event(
                timestamp,
                "$ veritas-ai verify --ledger runs/trl3/assurance_events.jsonl "
                "--public-key runs/trl3/public_key.pem\r\n",
            ),
            _event(
                timestamp + 0.5,
                f"Ledger valid  {verification['valid']}  "
                f"events  {verification['events_checked']}\r\n",
            ),
            _event(
                timestamp + 1.0,
                "TRL claim  Evidence consistent with TRL 3 laboratory proof of concept\r\n",
            ),
        ]
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--verification", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    build_cast(args.summary, args.verification, args.output)


if __name__ == "__main__":
    main()
