# Method

The method is deliberately staged. It first checks that the assurance mechanism can detect known changes under controlled conditions. More complex operational evaluation is deferred until a representative environment and adoption partner are available.

## Data generation

A fixed seed defines 5,000 labelled windows. The first 2,500 support training, 500 support calibration, 500 establish the reference envelope, and six groups of 250 exercise the monitoring scenarios. Each window maps to one or more safe synthetic TCP flows and one authentication event. A feature builder checks the complete flow-to-window mapping and then aggregates Zeek connection fields and authentication evidence. Ground-truth labels are joined only for the controlled offline evaluation.

The accompanying PCAP contains no exploit payloads. A separate Docker-backed gate processes all 41,248 default-seed flows with the digest-pinned official Zeek 8.0.9 LTS image. It validates the resulting JSON `conn.log` and rebuilds `observations.jsonl` from that output before model training, baselining, and monitoring.

## Security model

XGBoost is the primary multiclass classifier. A multinomial logistic regression provides a transparent comparison. Both use the same chronological split and feature contract. Only the XGBoost native JSON model is persisted.

## Assurance measurements

The baseline records per-class error rates, macro F1, expected calibration error, confidence, feature distributions, latency, and missingness. Monitoring uses Population Stability Index, a one-sided CUSUM, integrity hashes, and labelled deterioration where labels exist.

## Decisions

The policy returns `continue`, `investigate`, `recalibrate`, or `withdraw`. These outputs are advisory. They do not change the classifier or enforce a network response.
