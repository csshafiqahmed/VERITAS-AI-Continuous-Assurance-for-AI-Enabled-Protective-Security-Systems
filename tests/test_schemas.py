import json
from pathlib import Path

from jsonschema import validate

from veritas_ai.io import read_json, read_jsonl, write_json
from veritas_ai.ledger import sign_events, write_verification_report


def _schema(repository: Path, name: str, legacy: bool = False) -> dict[str, object]:
    root = repository / "schemas"
    if legacy:
        root = root / "1.0"
    return json.loads((root / name).read_text(encoding="utf-8"))


def test_current_public_evidence_schemas_accept_recovery_fields(tmp_path: Path) -> None:
    repository = Path(__file__).parents[1]
    event = {
        "scenario": "recovery_after_investigation",
        "action": "continue",
        "operator_acknowledged": True,
        "stable_window_count": 2,
        "recovery_checks": [
            {
                "window": window,
                "sample_count": 125,
                "labels_available": True,
                "action": "continue",
                "reasons": ["inside_reference_envelope"],
                "maximum_psi": 0.05,
                "telemetry_missingness": 0.0,
                "integrity": {"model_matches": True, "policy_matches": True},
                "within_warning_envelope": True,
            }
            for window in (1, 2)
        ],
    }
    ledger = tmp_path / "events.jsonl"
    public_key = tmp_path / "public.pem"
    sign_events(
        [event],
        ledger,
        public_key,
        evidence_bindings={
            "schema_version": "1.1.0",
            "version": "0.2.0",
            "artifacts": {"baseline.json": "a" * 64},
        },
    )
    records = read_jsonl(ledger)
    for record in records:
        validate(record, _schema(repository, "assurance_event.schema.json"))

    report_path = tmp_path / "verification.json"
    write_verification_report(ledger, public_key, report_path)
    validate(read_json(report_path), _schema(repository, "verification_report.schema.json"))

    baseline = {
        "schema_version": "1.1.0",
        "model_sha256": "a" * 64,
        "policy_sha256": "b" * 64,
        "thresholds": {},
        "labelled_metrics": {},
        "feature_profiles": {},
    }
    model_manifest = {
        "schema_version": "1.1.0",
        "model_type": "XGBClassifier",
        "model_format": "native_xgboost_json",
        "model_sha256": "a" * 64,
        "features": [],
        "classes": [],
    }
    summary = {
        "schema_version": "1.1.0",
        "version": "0.2.0",
        "trl_claim": "Evidence consistent with TRL 3 laboratory proof of concept",
        "limitations": ["not_trl_6"],
        "demonstration": {
            "mode": "guided_reviewer",
            "telemetry_source": "synthetic_zeek_compatible",
            "zeek_validated": False,
            "operator_acknowledged": True,
            "recovery_window_count": 2,
        },
        "scenario_actions": {"recovery_after_investigation": "continue"},
        "ledger_valid": True,
        "artifacts": {},
    }
    validate(baseline, _schema(repository, "baseline.schema.json"))
    validate(model_manifest, _schema(repository, "model_manifest.schema.json"))
    validate(summary, _schema(repository, "run_summary.schema.json"))


def test_preserved_legacy_schema_accepts_version_one_record(tmp_path: Path) -> None:
    repository = Path(__file__).parents[1]
    ledger = tmp_path / "legacy.jsonl"
    public_key = tmp_path / "legacy.pem"
    sign_events([{"action": "continue"}], ledger, public_key, schema_version="1.0")

    for record in read_jsonl(ledger):
        validate(record, _schema(repository, "assurance_event.schema.json", legacy=True))

    legacy_summary = {
        "schema_version": "1.0",
        "version": "0.1.0",
        "trl_claim": "Evidence consistent with TRL 3 laboratory proof of concept",
        "limitations": ["not_trl_6"],
        "scenario_actions": {},
        "ledger_valid": True,
        "artifacts": {},
    }
    legacy_path = tmp_path / "summary.json"
    write_json(legacy_path, legacy_summary)
    validate(
        read_json(legacy_path),
        _schema(repository, "run_summary.schema.json", legacy=True),
    )
