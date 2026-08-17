"""Ed25519 signed append-only assurance ledger."""

from __future__ import annotations

import base64
import binascii
import json
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from veritas_ai.constants import SCHEMA_VERSION
from veritas_ai.io import canonical_json, sha256_bytes, write_json, write_jsonl

LEDGER_SEAL_TYPE = "seal"
LEDGER_EVENT_TYPE = "event"


def _signed_record(
    private_key: Ed25519PrivateKey,
    index: int,
    previous_hash: str,
    record_type: str,
    event: dict[str, Any],
) -> dict[str, Any]:
    unsigned = {
        "schema_version": SCHEMA_VERSION,
        "index": index,
        "previous_hash": previous_hash,
        "record_type": record_type,
        "event": event,
    }
    event_hash = sha256_bytes(canonical_json(unsigned))
    signature = base64.b64encode(private_key.sign(event_hash.encode("ascii"))).decode("ascii")
    return {**unsigned, "event_hash": event_hash, "signature": signature}


def sign_events(
    events: list[dict[str, Any]], ledger_path: Path, public_key_path: Path
) -> list[dict[str, Any]]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    previous_hash = "0" * 64
    records: list[dict[str, Any]] = []
    for index, event in enumerate(events):
        record = _signed_record(
            private_key,
            index,
            previous_hash,
            LEDGER_EVENT_TYPE,
            event,
        )
        records.append(record)
        previous_hash = str(record["event_hash"])
    seal = _signed_record(
        private_key,
        len(events),
        previous_hash,
        LEDGER_SEAL_TYPE,
        {
            "event_count": len(events),
            "terminal_event_hash": previous_hash,
        },
    )
    records.append(seal)
    write_jsonl(ledger_path, records)
    public_key_path.parent.mkdir(parents=True, exist_ok=True)
    public_key_path.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return records


def verify_ledger(ledger_path: Path, public_key_path: Path) -> dict[str, Any]:
    key = serialization.load_pem_public_key(public_key_path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Verification key is not Ed25519")
    previous_hash = "0" * 64
    checked = 0
    error: str | None = None
    try:
        lines = [
            line for line in ledger_path.read_text(encoding="utf-8").splitlines() if line.strip()
        ]
        seal_seen = False
        for line_number, line in enumerate(lines, start=1):
            record = json.loads(line)
            if record["schema_version"] != SCHEMA_VERSION:
                raise ValueError(f"Unsupported schema version at line {line_number}")
            unsigned = {
                "schema_version": record["schema_version"],
                "index": record["index"],
                "previous_hash": record["previous_hash"],
                "record_type": record["record_type"],
                "event": record["event"],
            }
            if record["index"] != line_number - 1 or record["previous_hash"] != previous_hash:
                raise ValueError(f"Broken chain at line {line_number}")
            calculated = sha256_bytes(canonical_json(unsigned))
            if calculated != record["event_hash"]:
                raise ValueError(f"Hash mismatch at line {line_number}")
            key.verify(
                base64.b64decode(record["signature"], validate=True),
                calculated.encode("ascii"),
            )
            record_type = record["record_type"]
            event = record["event"]
            if not isinstance(event, dict):
                raise ValueError(f"Event payload is not an object at line {line_number}")
            if record_type == LEDGER_EVENT_TYPE:
                if seal_seen:
                    raise ValueError(f"Event follows terminal seal at line {line_number}")
                checked += 1
            elif record_type == LEDGER_SEAL_TYPE:
                if seal_seen or line_number != len(lines):
                    raise ValueError(f"Terminal seal is not final at line {line_number}")
                if event.get("event_count") != checked:
                    raise ValueError(f"Terminal event count mismatch at line {line_number}")
                if event.get("terminal_event_hash") != previous_hash:
                    raise ValueError(f"Terminal event hash mismatch at line {line_number}")
                seal_seen = True
            else:
                raise ValueError(f"Unknown record type at line {line_number}")
            previous_hash = calculated
        if not seal_seen:
            raise ValueError("Ledger is missing a signed terminal seal")
    except (
        InvalidSignature,
        KeyError,
        TypeError,
        ValueError,
        binascii.Error,
        json.JSONDecodeError,
    ) as exc:
        error = str(exc) or exc.__class__.__name__
    return {
        "schema_version": SCHEMA_VERSION,
        "valid": error is None,
        "events_checked": checked,
        "error": error,
        "ledger_sha256": sha256_bytes(ledger_path.read_bytes()),
    }


def write_verification_report(
    ledger_path: Path, public_key_path: Path, output_path: Path
) -> dict[str, Any]:
    report = verify_ledger(ledger_path, public_key_path)
    write_json(output_path, report)
    return report
