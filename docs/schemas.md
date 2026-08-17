# Machine-readable schemas

The versioned JSON Schemas in the repository describe the public evidence formats for `v0.1.0`.

| Artifact | Schema |
|---|---|
| Model manifest | `schemas/model_manifest.schema.json` |
| Assurance baseline | `schemas/baseline.schema.json` |
| Signed event | `schemas/assurance_event.schema.json` |
| Run summary | `schemas/run_summary.schema.json` |
| Verification report | `schemas/verification_report.schema.json` |

Schema version `1.0` is independent of the package version. Unknown top-level fields are permitted only where a schema explicitly allows them.
