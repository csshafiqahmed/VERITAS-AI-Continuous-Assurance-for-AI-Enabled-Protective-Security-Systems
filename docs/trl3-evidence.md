# TRL 3 evidence matrix

The project uses a conservative maturity boundary. The released artifacts are intended to demonstrate analytical and experimental proof of critical functions, not performance in a representative operational environment.

| Critical function | Planned evidence | Current status |
|---|---|---|
| Deterministic telemetry generation | Repeated data hashes | Verified by deterministic generation tests |
| Security model training | Held-out labelled evaluation | Verified in the automatic and guided workflows |
| Reference envelope | Versioned baseline JSON | Verified by schema and calculation tests |
| Degradation detection | Six controlled scenarios | Verified with the expected advisory sequence |
| Integrity assurance | Ed25519 signed hash chain, terminal-seal artifact bindings, and checkpoint reconciliation | Verified with positive, artifact-modification, symlink, summary-modification, checkpoint-mismatch, and tampered-ledger tests |
| Reproducibility | Clean Codespace and container run | Local gate verified, hosted gates run for the release candidate |
| Guided reviewer workflow | Live staged run, operator checkpoint, signed recovery checks, and tamper demonstration | Verified by workflow, archive, and Streamlit interaction tests |

The evidence does not demonstrate representative users, real security operations, production traffic, deployment safety, partner adoption, or TRL 6.
