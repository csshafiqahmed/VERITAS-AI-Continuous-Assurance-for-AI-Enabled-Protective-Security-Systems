"""Ed25519 signed append-only assurance ledger."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from veritas_ai.constants import SCHEMA_VERSION
from veritas_ai.io import canonical_json, sha256_bytes, write_json, write_jsonl


def sign_events(
    events: list[dict[str, Any]], ledger_path: Path, public_key_path: Path
) -> list[dict[str, Any]]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    previous_hash = "0" * 64
    records: list[dict[str, Any]] = []
    for index, event in enumerate(events):
        unsigned = {
            "schema_version": SCHEMA_VERSION,
            "index": index,
            "previous_hash": previous_hash,
            "event": event,
        }
        event_hash = sha256_bytes(canonical_json(unsigned))
        signature = base64.b64encode(private_key.sign(event_hash.encode("ascii"))).decode("ascii")
        record = {**unsigned, "event_hash": event_hash, "signature": signature}
        records.append(record)
        previous_hash = event_hash
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
        for line_number, line in enumerate(
            ledger_path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if not line.strip():
                continue
            record = json.loads(line)
            unsigned = {
                "schema_version": record["schema_version"],
                "index": record["index"],
                "previous_hash": record["previous_hash"],
                "event": record["event"],
            }
            if record["index"] != checked or record["previous_hash"] != previous_hash:
                raise ValueError(f"Broken chain at line {line_number}")
            calculated = sha256_bytes(canonical_json(unsigned))
            if calculated != record["event_hash"]:
                raise ValueError(f"Hash mismatch at line {line_number}")
            key.verify(base64.b64decode(record["signature"]), calculated.encode("ascii"))
            previous_hash = calculated
            checked += 1
    except (InvalidSignature, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
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
