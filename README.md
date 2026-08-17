# VERITAS-AI

[![CI](https://github.com/csshafiqahmed/VERITAS-AI-Continuous-Assurance-for-AI-Enabled-Protective-Security-Systems/actions/workflows/ci.yml/badge.svg)](https://github.com/csshafiqahmed/VERITAS-AI-Continuous-Assurance-for-AI-Enabled-Protective-Security-Systems/actions/workflows/ci.yml)
[![CodeQL](https://github.com/csshafiqahmed/VERITAS-AI-Continuous-Assurance-for-AI-Enabled-Protective-Security-Systems/actions/workflows/codeql.yml/badge.svg)](https://github.com/csshafiqahmed/VERITAS-AI-Continuous-Assurance-for-AI-Enabled-Protective-Security-Systems/actions/workflows/codeql.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

VERITAS-AI is a laboratory proof of concept for baselining and monitoring an AI-enabled protective security capability. It uses a synthetic network intrusion classifier as the system under assurance. The assurance layer observes data quality, distribution change, labelled performance when labels exist, model integrity, and policy integrity.

The model input is built rather than copied from the generator. Connection telemetry, authentication events, and separate labels are joined through explicit stable window and flow identifiers. The Docker-backed route rebuilds the same 5,000 observation windows from Zeek's output before training and monitoring.

The project is designed to produce evidence consistent with Technology Readiness Level 3. It is not an operational security product, a certified system, or evidence of TRL 6.

## Quick start

Python 3.12 and [`uv`](https://docs.astral.sh/uv/) are required.

```bash
uv sync --all-groups
uv run veritas-ai demo --output runs/trl3
uv run veritas-ai verify \
  --ledger runs/trl3/assurance_events.jsonl \
  --public-key runs/trl3/public_key.pem
```

Run the local dashboard after the demonstration.

```bash
uv run veritas-ai dashboard --run runs/trl3
```

To regenerate the network evidence through Zeek, use a machine with Docker. The command runs the official Zeek 8.0.9 LTS image by immutable multi-platform digest. The container has no network access, all Linux capabilities are dropped, and its root filesystem is read-only.

```bash
uv run veritas-ai demo --regenerate-zeek --output runs/trl3
```

The validated JSON connection log is saved at `runs/trl3/data/zeek-output/conn.log`. Its hash, record count, image reference, reported Zeek version, and required-field contract are recorded in the dataset manifest. `observations.jsonl` is then rebuilt from this log, `auth.jsonl`, and `labels.jsonl`.

## Assurance outcomes

The demonstrator emits four advisory outcomes.

| Outcome | Meaning |
|---|---|
| `continue` | Observed evidence remains inside the demonstration envelope |
| `investigate` | A warning or incomplete evidence needs operator review |
| `recalibrate` | Persistent labelled deterioration supports model recalibration |
| `withdraw` | Critical degradation or an integrity mismatch makes continued reliance unsafe |

These outcomes do not retrain a model, block traffic, or replace a security operator.

## Evidence boundaries

- All included data are deterministically generated and contain no personal information.
- PCAP records contain safe synthetic traffic and no exploit payloads.
- Accuracy and false-negative measures are reported only for labelled windows.
- Unlabelled monitoring reports drift, integrity, latency, and missingness only.
- External adoption, representative cyber-range trials, and operational validation are future work.

See the [technical specification](docs/specification.md), [threat model](docs/threat-model.md), and [TRL 3 evidence matrix](docs/trl3-evidence.md).

## Licence and citation

The software is available under the [Apache License 2.0](LICENSE). Citation metadata are provided in [`CITATION.cff`](CITATION.cff).
