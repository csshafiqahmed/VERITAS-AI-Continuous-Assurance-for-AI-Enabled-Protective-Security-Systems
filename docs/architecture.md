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
