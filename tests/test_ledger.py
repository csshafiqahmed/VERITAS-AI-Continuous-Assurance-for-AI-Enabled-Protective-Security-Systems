import json
from pathlib import Path

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
