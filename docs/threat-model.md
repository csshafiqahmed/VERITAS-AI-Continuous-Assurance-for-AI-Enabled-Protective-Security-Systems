# Threat model

The threat model focuses on assurance evidence rather than attempting to cover every attack against a deployed security product.

## Protected assets

- Model identity and feature contract
- Baseline and policy integrity
- Monitoring-event order and content
- Accuracy of evidence provenance

## Considered failures and adversaries

- Accidental or malicious model replacement
- Baseline or policy modification
- Missing or malformed telemetry
- Feature-distribution change
- Labelled performance deterioration
- Removal, insertion, or modification of audit events

## Controls

- SHA-256 hashes bind models, policies, schemas, and event order
- Ed25519 signatures authenticate each ledger record and its mandatory terminal seal
- The signed terminal event count and hash make removal of a valid ledger suffix detectable
- The current terminal seal binds core artifact hashes and displayed run provenance
- The acknowledgement checkpoint binds substantive first-phase evidence before recovery
- Regular-file and path-boundary checks reject symlinked or escaping evidence paths
- Dataset file hashes, model identity, baseline identity, summary metadata, and the stored verification report are reconciled before display or download
- Strict schema validation rejects malformed and non-finite data
- Native XGBoost JSON avoids executable deserialisation
- Private signing material is never written to release artifacts

## Exclusions

The prototype does not provide endpoint containment, packet blocking, identity management, malware analysis, key management infrastructure, or protection against compromise of the host running the demonstration.
