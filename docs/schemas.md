# Machine-readable schemas

The root JSON Schemas describe the current `v0.2.0` evidence formats using schema version `1.1.0`. Preserved version `1.0` schemas are available under `schemas/1.0` for evidence produced by `v0.1.0`.

Ledger verification accepts a complete `1.0` or `1.1.0` chain. It rejects unknown versions and any chain that mixes versions. New verification reports identify the schema version found in the verified ledger.

| Artifact | Schema |
|---|---|
| Model manifest | `schemas/model_manifest.schema.json` |
| Assurance baseline | `schemas/baseline.schema.json` |
| Signed event or terminal seal | `schemas/assurance_event.schema.json` |
| Run summary | `schemas/run_summary.schema.json` |
| Verification report | `schemas/verification_report.schema.json` |

The `1.1.0` assurance-event schema adds optional signed recovery evidence. The run-summary schema adds the demonstration mode, telemetry source, Zeek validation state, operator acknowledgement, and number of stable recovery windows.

Progress updates and the local guided-run state are implementation details. They are excluded from the public evidence schemas and release bundles. Unknown top-level fields are permitted only where a schema explicitly allows them.
