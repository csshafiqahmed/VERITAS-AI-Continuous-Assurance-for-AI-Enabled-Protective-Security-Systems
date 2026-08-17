"""End-to-end TRL 3 demonstration workflow."""

from __future__ import annotations

import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from veritas_ai import __version__
from veritas_ai.assurance import create_baseline, monitor_records
from veritas_ai.constants import DEFAULT_SEED, SCHEMA_VERSION, ZEEK_IMAGE
from veritas_ai.data import SCENARIOS, generate_dataset, process_with_zeek
from veritas_ai.io import read_jsonl, sha256_file, write_json
from veritas_ai.ledger import sign_events, write_verification_report
from veritas_ai.model import train_model


def _git_revision() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else "unavailable"


def run_demo(
    output: Path, regenerate_zeek: bool = False, seed: int = DEFAULT_SEED
) -> dict[str, Any]:
    output.mkdir(parents=True, exist_ok=True)
    data_dir = output / "data"
    model_dir = output / "model"
    manifest = generate_dataset(data_dir, seed=seed)
    if regenerate_zeek:
        manifest = process_with_zeek(data_dir, ZEEK_IMAGE)

    model_manifest = train_model(data_dir / "observations.jsonl", model_dir, seed)
    baseline_path = output / "baseline.json"
    create_baseline(model_dir, data_dir / "observations.jsonl", baseline_path)
    records = read_jsonl(data_dir / "observations.jsonl")
    events: list[dict[str, Any]] = []
    for scenario in SCENARIOS:
        scenario_records = [record for record in records if record.get("scenario") == scenario]
        kwargs: dict[str, Any] = {}
        if scenario == "benign_workload_change":
            kwargs["context_approved"] = True
        elif scenario == "model_replacement":
            kwargs["observed_model_hash"] = "0" * 64
        elif scenario == "recovery_after_investigation":
            kwargs["operator_acknowledged"] = True
            kwargs["stable_window_count"] = 2
        events.append(
            monitor_records(
                model_dir,
                baseline_path,
                scenario_records,
                labels_available=True,
                **kwargs,
            )
        )

    ledger_path = output / "assurance_events.jsonl"
    public_key_path = output / "public_key.pem"
    sign_events(events, ledger_path, public_key_path)
    verification = write_verification_report(
        ledger_path, public_key_path, output / "verification_report.json"
    )
    summary: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "version": __version__,
        "completed_at": datetime.now(UTC).isoformat(),
        "git_revision": _git_revision(),
        "python": platform.python_version(),
        "seed": seed,
        "trl_claim": "Evidence consistent with TRL 3 laboratory proof of concept",
        "limitations": [
            "synthetic_data",
            "no_external_partner_validation",
            "no_representative_operational_environment",
            "not_trl_6",
        ],
        "dataset_manifest": manifest,
        "model_manifest": model_manifest,
        "scenario_actions": {event["scenario"]: event["action"] for event in events},
        "ledger_valid": verification["valid"],
        "artifacts": {
            "baseline.json": sha256_file(output / "baseline.json"),
            "assurance_events.jsonl": sha256_file(ledger_path),
            "public_key.pem": sha256_file(public_key_path),
            "verification_report.json": sha256_file(output / "verification_report.json"),
        },
    }
    write_json(output / "run_summary.json", summary)
    return summary
