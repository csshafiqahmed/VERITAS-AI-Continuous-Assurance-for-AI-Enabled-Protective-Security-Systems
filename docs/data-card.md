# Synthetic data card

The dataset exists to test software behaviour under known conditions. It is not intended to represent the full variation, ambiguity, or adversarial pressure found in operational security telemetry.

## Composition

- 5,000 deterministic observation windows
- 41,248 deterministic connection records under the default seed
- Benign activity and four synthetic security-event classes
- Safe PCAP traffic and Zeek-compatible connection records
- Authentication events and separate ground-truth labels
- Training, calibration, baseline, and monitoring partitions

Each label record maps one stable window identifier to its expected flow identifiers. The feature builder verifies a complete one-to-one flow assignment, joins the matching authentication event, and aggregates duration, byte, packet, destination, service, connection-rate, and missingness evidence into one observation. Labels remain a separate source until this controlled offline join.

## Privacy and safety

Addresses are drawn from private or documentation ranges. Names, credentials, personal information, malware, and exploit payloads are absent. The generator does not capture a live interface.

## Appropriate use

The data support reproducibility tests, metric validation, failure injection, and demonstration of the assurance workflow. They must not support claims about operational detection rates or population-level security behaviour.
