"""Public VERITAS-AI command-line interface."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Annotated

import typer

from veritas_ai.assurance import create_baseline, monitor_dataset
from veritas_ai.data import build_observations
from veritas_ai.ledger import write_verification_report
from veritas_ai.model import train_model
from veritas_ai.workflow import run_demo

app = typer.Typer(
    no_args_is_help=True,
    help="Continuous assurance proof of concept for an AI-enabled security classifier.",
)


def _show(value: object) -> None:
    typer.echo(json.dumps(value, indent=2, sort_keys=True))


@app.command()
def demo(
    output: Annotated[Path, typer.Option(help="Directory for generated evidence")] = Path(
        "runs/trl3"
    ),
    regenerate_zeek: Annotated[
        bool, typer.Option(help="Process the generated PCAP with the pinned Zeek container")
    ] = False,
) -> None:
    """Run the complete deterministic laboratory demonstration."""
    _show(run_demo(output, regenerate_zeek=regenerate_zeek))


@app.command("train")
def train_command(
    telemetry: Annotated[Path, typer.Option(exists=True, help="Observation JSONL")],
    auth: Annotated[Path, typer.Option(exists=True, help="Authentication-event JSONL")],
    labels: Annotated[Path, typer.Option(exists=True, help="Ground-truth JSONL")],
    output: Annotated[Path, typer.Option(help="Model output directory")],
) -> None:
    """Train the laboratory classifier from labelled telemetry."""
    dataset_path = output / "training_observations.jsonl"
    feature_builder = build_observations(telemetry, auth, labels, dataset_path)
    _show(
        {
            "feature_builder": feature_builder,
            "model_manifest": train_model(dataset_path, output),
        }
    )


@app.command("baseline")
def baseline_command(
    model: Annotated[Path, typer.Option(exists=True, help="Model directory")],
    dataset: Annotated[Path, typer.Option(exists=True, help="Observation JSONL")],
    output: Annotated[Path, typer.Option(help="Baseline JSON path")],
) -> None:
    """Establish a labelled reference envelope."""
    _show(create_baseline(model, dataset, output))


@app.command("monitor")
def monitor_command(
    model: Annotated[Path, typer.Option(exists=True, help="Model directory")],
    baseline: Annotated[Path, typer.Option(exists=True, help="Baseline JSON")],
    stream: Annotated[Path, typer.Option(exists=True, help="Monitoring JSONL")],
    labels: Annotated[Path | None, typer.Option(help="Optional ground-truth JSONL")] = None,
    output: Annotated[Path, typer.Option(help="Monitoring output directory")] = Path(
        "runs/monitor"
    ),
) -> None:
    """Evaluate one monitoring stream without taking an automated security action."""
    if labels is not None and not labels.exists():
        raise typer.BadParameter("Labels path does not exist")
    _show(monitor_dataset(model, baseline, stream, output, labels_path=labels))


@app.command("verify")
def verify_command(
    ledger: Annotated[Path, typer.Option(exists=True, help="Signed JSONL ledger")],
    public_key: Annotated[Path, typer.Option(exists=True, help="Ed25519 public key")],
    output: Annotated[Path | None, typer.Option(help="Optional verification report")] = None,
) -> None:
    """Verify event order, hashes, and Ed25519 signatures."""
    report_path = output or ledger.with_name("verification_report.json")
    report = write_verification_report(ledger, public_key, report_path)
    _show(report)
    if not report["valid"]:
        raise typer.Exit(code=1)


@app.command("dashboard")
def dashboard_command(
    run: Annotated[
        Path | None,
        typer.Option(exists=True, help="Optional completed demonstration directory"),
    ] = None,
    runs_root: Annotated[
        Path,
        typer.Option(help="Directory for guided reviewer runs"),
    ] = Path("runs/reviewer"),
    address: Annotated[
        str,
        typer.Option(help="Streamlit bind address"),
    ] = "127.0.0.1",
) -> None:
    """Open the guided demonstration and signed evidence application."""
    if address not in {"127.0.0.1", "0.0.0.0"}:
        raise typer.BadParameter("Address must be 127.0.0.1 or 0.0.0.0")
    command = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(Path(__file__).with_name("dashboard.py")),
        "--server.address",
        address,
        "--server.port",
        "8501",
        "--server.headless",
        "true",
        "--",
        "--runs-root",
        str(runs_root.resolve()),
    ]
    if run is not None:
        command.extend(["--run", str(run.resolve())])
    raise typer.Exit(code=subprocess.run(command, check=False).returncode)


if __name__ == "__main__":
    app()
