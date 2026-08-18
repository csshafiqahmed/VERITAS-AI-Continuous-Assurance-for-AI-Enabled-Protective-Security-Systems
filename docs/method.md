# Method

The method is deliberately staged. It first checks that the assurance mechanism can detect known changes under controlled conditions. More complex operational evaluation is deferred until a representative environment and adoption partner are available.

## Data generation

A fixed seed defines 5,000 windows. The first 2,500 support training, 500 support calibration, 500 establish the reference envelope, and six groups of 250 exercise the monitoring scenarios. Each window maps to one or more safe synthetic TCP flows and one authentication event. A feature builder checks the complete flow-to-window mapping and then aggregates Zeek connection fields and authentication evidence. Ground-truth labels are joined only when they are available for controlled offline evaluation. The partial telemetry scenario deliberately withholds them.

The accompanying PCAP contains no exploit payloads. A separate Docker-backed gate processes all 41,248 default-seed flows with the digest-pinned official Zeek 8.0.9 LTS image. It validates the resulting JSON `conn.log` and rebuilds `observations.jsonl` from that output before model training, baselining, and monitoring.

## Security model

XGBoost is the primary multiclass classifier. A multinomial logistic regression provides a transparent comparison. Both use the same chronological split and feature contract. Only the XGBoost native JSON model is persisted.

## Assurance measurements

The baseline records per-class error rates, macro F1, expected calibration error, confidence, feature distributions, latency, and missingness. Monitoring uses Population Stability Index, a one-sided confidence CUSUM, integrity hashes, and labelled deterioration where labels exist. In an unlabelled stream, a CUSUM value at or above the configured five-sigma decision interval produces an `investigate` recommendation. It does not imply a current accuracy or false-negative estimate.

## Decisions

The policy returns `continue`, `investigate`, `recalibrate`, or `withdraw`. These outputs are advisory. They do not change the classifier or enforce a network response.

The guided workflow stops after the model replacement scenario. Recovery begins only after the reviewer acknowledges the investigation. The 250 recovery observations form two ordered 125-observation windows drawn from stratified reference conditions. Both windows must retain model and policy integrity and remain below warning thresholds. If either check fails, the final event adopts the most severe observed outcome.
