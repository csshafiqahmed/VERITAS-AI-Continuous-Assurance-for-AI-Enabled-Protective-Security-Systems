# Technical specification

This specification defines the public behaviour of the first proof of concept. It separates functions that are implemented from claims that require later operational evidence.

## Objective

The demonstrator establishes a reference envelope for an AI-enabled network intrusion classifier. It then evaluates controlled monitoring windows and records whether the evidence supports continued use, investigation, recalibration, or withdrawal.

## Inputs

- Safe deterministic PCAP traffic
- Zeek JSON connection records
- Deterministic authentication events
- Ground-truth labels for offline experiments
- A native XGBoost JSON model
- A versioned monitoring policy

Connection telemetry, authentication events, and labels remain separate inputs. The offline feature builder requires unique window identifiers and a complete non-overlapping mapping from each generated flow to one window. It rejects unknown, repeated, or missing flows before producing model observations.

The independent `train` command performs this three-source join before fitting the model. The `monitor` command accepts ground truth separately and joins it by `window_id`. Omitting ground truth suppresses accuracy, calibration, and false-negative calculations even if an incidental label field appears in the monitoring stream.

## Outputs

- A model manifest containing hashes, features, classes, and dependency versions
- A baseline containing labelled metrics and feature distributions
- An append-only signed assurance ledger with a mandatory terminal seal
- A run summary containing environment and evidence provenance
- A public Ed25519 verification key
- A machine-readable verification report

## Guided reviewer demonstration

Version 0.2.0 provides a two-mode Streamlit application. Guided Demonstration executes the laboratory workflow. Signed Evidence Review opens only after the ledger and summary have been reconciled.

The guided workflow generates 5,000 windows, trains the XGBoost detector and logistic comparison, establishes the reference envelope, and evaluates six controlled scenarios. Partial telemetry loss is evaluated without ground truth. Its accuracy, calibration, and false-negative measures must remain unavailable.

The workflow pauses after the model-integrity failure. A reviewer acknowledgement then permits two ordered recovery windows to be evaluated. Both windows must remain within the warning envelope and preserve model and policy integrity before the signed recovery event can recommend `continue`.

Docker-backed Zeek processing is optional in the reviewer interface. The portable route uses generated Zeek-format records and states that limitation explicitly. Selecting Zeek requires the digest-pinned container route to complete. The workflow must not silently fall back after Zeek has been selected.

Runtime progress is observational. A stage is marked complete only after the associated computation or artifact check completes. Progress events are not public assurance evidence and are not placed in the signed ledger.

## Schema compatibility

New evidence uses schema version `1.1.0`. Ledger verification continues to accept internally consistent version `1.0` ledgers from the first release. Mixed-version ledgers and unknown schema versions are rejected.

The version `1.1.0` assurance event can carry an operator acknowledgement and two signed recovery checks. The run summary records the demonstration mode, telemetry source, Zeek status, acknowledgement state, and recovery-window count.

## Evidence boundary

Labelled metrics are unavailable when monitoring data have no ground truth. The system must not infer current accuracy, calibration, or false-negative rates from drift alone. All decisions are advisory and require human interpretation.

The acknowledgement records a laboratory workflow action. It does not identify or legally attest an operator.

The terminal ledger seal signs the final event hash and expected event count. Verification fails if a signed event suffix or the seal itself is removed. The recorded Git revision is resolved only from the source project checkout. Installed wheels outside that checkout report the revision as unavailable rather than adopting the revision of an unrelated working directory.
