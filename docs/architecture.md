# Architecture

The prototype separates the security model from the assurance mechanism so that monitoring evidence can be inspected independently.

```text
Synthetic PCAP and authentication events
                 |
                 v
          Zeek and feature builder
                 |
                 v
        XGBoost security classifier
                 |
                 v
 Baseline and continuous assurance engine
                 |
                 v
 Advisory decision and signed evidence ledger
                 |
                 v
       CLI and two-mode dashboard
```

Every complete run records the code version, schema version, model hash, policy hash, and data-generation seed. An integrity mismatch is treated separately from statistical deterioration.

The dashboard has a guided execution mode and a signed review mode. Guided Demonstration calls the same data, model, baseline, monitoring, signing, and verification functions as the command line. It records only recoverable workflow state before acknowledgement. No trusted assurance result or private key is stored in that state.

Signed Evidence Review remains read-only. Before displaying a value, it verifies the Ed25519 ledger, requires a signed terminal seal, checks the event count, and confirms that the summary decisions exactly match the signed events. A modified or truncated ledger and an inconsistent summary are rejected rather than displayed.
