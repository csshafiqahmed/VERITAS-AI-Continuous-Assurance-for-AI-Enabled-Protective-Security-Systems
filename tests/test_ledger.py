import json
from pathlib import Path

import pytest

from veritas_ai.ledger import sign_events, verify_ledger


def test_ledger_verifies_and_tampering_fails(tmp_path: Path) -> None:
    ledger = tmp_path / "events.jsonl"
    public_key = tmp_path / "public_key.pem"
    sign_events([{"action": "continue"}, {"action": "investigate"}], ledger, public_key)
    report = verify_ledger(ledger, public_key)
    assert report["valid"] is True
    assert report["events_checked"] == 2

    lines = ledger.read_text(encoding="utf-8").splitlines()
    changed = json.loads(lines[1])
    changed["event"]["action"] = "continue"
    lines[1] = json.dumps(changed)
    ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert verify_ledger(ledger, public_key)["valid"] is False


def test_ledger_rejects_signed_prefix_truncation(tmp_path: Path) -> None:
    ledger = tmp_path / "events.jsonl"
    public_key = tmp_path / "public_key.pem"
    sign_events([{"action": "continue"}, {"action": "withdraw"}], ledger, public_key)

    lines = ledger.read_text(encoding="utf-8").splitlines()
    ledger.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
    report = verify_ledger(ledger, public_key)

    assert report["valid"] is False
    assert report["events_checked"] == 2
    assert report["error"] == "Ledger is missing a signed terminal seal"


def test_private_key_is_not_persisted(tmp_path: Path) -> None:
    sign_events([{"action": "continue"}], tmp_path / "events.jsonl", tmp_path / "public.pem")
    assert sorted(path.name for path in tmp_path.iterdir()) == ["events.jsonl", "public.pem"]


def test_legacy_schema_ledger_remains_verifiable(tmp_path: Path) -> None:
    ledger = tmp_path / "legacy.jsonl"
    public_key = tmp_path / "legacy-public.pem"
    sign_events(
        [{"action": "continue"}],
        ledger,
        public_key,
        schema_version="1.0",
    )

    report = verify_ledger(ledger, public_key)
    assert report["valid"] is True
    assert report["ledger_schema_version"] == "1.0"
    assert report["schema_version"] == "1.1.0"
    assert report["evidence_bindings"] is None


def test_terminal_seal_returns_verified_evidence_bindings(tmp_path: Path) -> None:
    ledger = tmp_path / "events.jsonl"
    public_key = tmp_path / "public.pem"
    bindings = {
        "version": "0.2.0",
        "artifacts": {"baseline.json": "a" * 64},
    }

    sign_events(
        [{"action": "continue"}],
        ledger,
        public_key,
        evidence_bindings=bindings,
    )

    report = verify_ledger(ledger, public_key)
    assert report["valid"] is True
    assert report["evidence_bindings"] == bindings


def test_legacy_schema_rejects_evidence_bindings(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="require the current schema"):
        sign_events(
            [{"action": "continue"}],
            tmp_path / "legacy.jsonl",
            tmp_path / "public.pem",
            schema_version="1.0",
            evidence_bindings={"version": "0.2.0"},
        )


def test_signing_rejects_an_unknown_schema(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Unsupported signing schema"):
        sign_events(
            [{"action": "continue"}],
            tmp_path / "events.jsonl",
            tmp_path / "public.pem",
            schema_version="2.0",
        )


def test_verification_rejects_non_object_evidence_bindings(tmp_path: Path) -> None:
    ledger = tmp_path / "events.jsonl"
    public_key = tmp_path / "public.pem"
    sign_events(
        [{"action": "continue"}],
        ledger,
        public_key,
        evidence_bindings=[],  # type: ignore[arg-type]
    )

    report = verify_ledger(ledger, public_key)
    assert report["valid"] is False
    assert report["error"] == "Evidence bindings are not an object at line 2"
    assert report["evidence_bindings"] is None


def test_mixed_schema_ledger_is_rejected(tmp_path: Path) -> None:
    ledger = tmp_path / "mixed.jsonl"
    public_key = tmp_path / "mixed-public.pem"
    sign_events([{"action": "continue"}], ledger, public_key)
    records = [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines()]
    records[-1]["schema_version"] = "1.0"
    ledger.write_text("\n".join(json.dumps(record) for record in records) + "\n", encoding="utf-8")

    report = verify_ledger(ledger, public_key)
    assert report["valid"] is False
    assert report["error"] == "Mixed schema versions at line 2"
