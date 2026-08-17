# Method

The method is deliberately staged. It first checks that the assurance mechanism can detect known changes under controlled conditions. More complex operational evaluation is deferred until a representative environment and adoption partner are available.

## Data generation

A fixed seed produces 5,000 labelled observations. The first 2,500 support training, 500 support calibration, 500 establish the reference envelope, and six groups of 250 exercise the monitoring scenarios. The accompanying PCAP contains safe synthetic TCP exchanges and no exploit payloads. A separate Docker-backed gate processes the PCAP with the digest-pinned official Zeek 8.0.9 LTS image and validates the resulting JSON `conn.log` before admitting its hash and provenance to the evidence manifest.

## Security model

XGBoost is the primary multiclass classifier. A multinomial logistic regression provides a transparent comparison. Both use the same chronological split and feature contract. Only the XGBoost native JSON model is persisted.

## Assurance measurements

The baseline records per-class error rates, macro F1, expected calibration error, confidence, feature distributions, latency, and missingness. Monitoring uses Population Stability Index, a one-sided CUSUM, integrity hashes, and labelled deterioration where labels exist.

## Decisions

The policy returns `continue`, `investigate`, `recalibrate`, or `withdraw`. These outputs are advisory. They do not change the classifier or enforce a network response.
