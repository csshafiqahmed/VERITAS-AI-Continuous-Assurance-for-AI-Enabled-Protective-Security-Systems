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

## Outputs

- A model manifest containing hashes, features, classes, and dependency versions
- A baseline containing labelled metrics and feature distributions
- An append-only signed assurance ledger
- A run summary containing environment and evidence provenance
- A public Ed25519 verification key
- A machine-readable verification report

## Evidence boundary

Labelled metrics are unavailable when monitoring data have no ground truth. The system must not infer current accuracy, calibration, or false-negative rates from drift alone. All decisions are advisory and require human interpretation.
