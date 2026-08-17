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
             CLI and dashboard
```

Every complete run records the code version, schema version, model hash, policy hash, and data-generation seed. An integrity mismatch is treated separately from statistical deterioration.

The dashboard is a read-only evidence view. Before displaying a value, it verifies the Ed25519 ledger, checks the event count, and confirms that the summary decisions exactly match the signed events. A modified ledger or inconsistent summary is rejected rather than displayed.
