import json
import math
import subprocess
from pathlib import Path

import pytest

from veritas_ai.constants import ZEEK_IMAGE
from veritas_ai.data import (
    build_observations,
    generate_dataset,
    process_with_zeek,
    validate_zeek_conn_log,
)
from veritas_ai.io import read_json, read_jsonl, write_jsonl


def _valid_zeek_record() -> dict[str, object]:
    return {
        "ts": 1.0,
        "uid": "C1",
        "id.orig_h": "192.0.2.1",
        "id.orig_p": 10000,
        "id.resp_h": "192.0.2.2",
        "id.resp_p": 443,
        "proto": "tcp",
        "duration": 0.5,
        "orig_bytes": 100,
        "resp_bytes": 200,
        "orig_pkts": 2,
        "resp_pkts": 2,
    }


def test_generation_is_deterministic(tmp_path: Path) -> None:
    first = generate_dataset(tmp_path / "first", count=60, seed=42)
    second = generate_dataset(tmp_path / "second", count=60, seed=42)
    assert first["files"] == second["files"]
    assert first["observation_count"] == 60
    assert first["connection_count"] > first["observation_count"]
    assert first["feature_builder"]["output_sha256"] == first["files"]["observations.jsonl"]


def test_zeek_log_validation_rejects_missing_fields(tmp_path: Path) -> None:
    conn_log = tmp_path / "conn.log"
    write_jsonl(conn_log, [{"ts": 1.0, "uid": "C1"}])
    with pytest.raises(ValueError, match="is missing"):
        validate_zeek_conn_log(conn_log)


def test_zeek_log_validation_rejects_empty_count_type_and_nonfinite_values(
    tmp_path: Path,
) -> None:
    conn_log = tmp_path / "conn.log"
    conn_log.write_text("", encoding="utf-8")
    with pytest.raises(ValueError, match="is empty"):
        validate_zeek_conn_log(conn_log)

    record = _valid_zeek_record()
    write_jsonl(conn_log, [record])
    with pytest.raises(ValueError, match="expected 2"):
        validate_zeek_conn_log(conn_log, expected_records=2)

    record["ts"] = True
    write_jsonl(conn_log, [record])
    with pytest.raises(ValueError, match="invalid timestamp"):
        validate_zeek_conn_log(conn_log)

    record["ts"] = 1.0
    record["proto"] = ""
    write_jsonl(conn_log, [record])
    with pytest.raises(ValueError, match="invalid protocol"):
        validate_zeek_conn_log(conn_log)

    record["proto"] = "tcp"
    record["orig_bytes"] = math.nan
    conn_log.write_text(json.dumps(record, allow_nan=True) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Out of range float values"):
        validate_zeek_conn_log(conn_log)


def test_process_with_zeek_records_pinned_provenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data_dir = tmp_path / "data"
    generate_dataset(data_dir, count=2, seed=42)
    commands: list[list[str]] = []

    def fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        if "--version" in command:
            return subprocess.CompletedProcess(command, 0, "zeek version 8.0.9\n", "")
        zeek_output = data_dir / "zeek-output"
        zeek_output.mkdir(parents=True, exist_ok=True)
        records = read_jsonl(data_dir / "conn.log")
        for record in records:
            record.pop("synthetic_zeek_compatible")
        write_jsonl(zeek_output / "conn.log", records)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr("veritas_ai.data.shutil.which", lambda _: "/usr/bin/docker")
    monkeypatch.setattr("veritas_ai.data.subprocess.run", fake_run)

    manifest = process_with_zeek(data_dir, ZEEK_IMAGE)
    persisted = read_json(data_dir / "dataset_manifest.json")
    assert manifest == persisted
    assert manifest["zeek"]["record_count"] == manifest["connection_count"]
    assert manifest["feature_builder"]["observation_count"] == 2
    assert manifest["zeek"]["image"] == ZEEK_IMAGE
    assert manifest["zeek"]["network_access"] == "disabled"
    assert all("none" in command for command in commands)
    assert all("ALL" in command for command in commands)


def test_process_with_zeek_rejects_mutable_image_reference(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="SHA-256 digest"):
        process_with_zeek(tmp_path, "zeek/zeek:8.0.9")


def test_process_with_zeek_requires_docker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("veritas_ai.data.shutil.which", lambda _: None)
    with pytest.raises(RuntimeError, match="Docker is required"):
        process_with_zeek(tmp_path, ZEEK_IMAGE)


def test_process_with_zeek_rejects_version_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("veritas_ai.data.shutil.which", lambda _: "/usr/bin/docker")
    monkeypatch.setattr(
        "veritas_ai.data.subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, "zeek version 9.0.0\n", ""),
    )
    with pytest.raises(RuntimeError, match="unexpected Zeek version"):
        process_with_zeek(tmp_path, ZEEK_IMAGE)


def test_process_with_zeek_requires_connection_log(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data_dir = tmp_path / "data"
    generate_dataset(data_dir, count=1, seed=42)
    monkeypatch.setattr("veritas_ai.data.shutil.which", lambda _: "/usr/bin/docker")
    monkeypatch.setattr(
        "veritas_ai.data.subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, "zeek version 8.0.9\n", ""),
    )
    with pytest.raises(RuntimeError, match="did not produce"):
        process_with_zeek(data_dir, ZEEK_IMAGE)


def test_feature_builder_rejects_window_and_flow_mismatches(tmp_path: Path) -> None:
    telemetry = tmp_path / "conn.log"
    auth = tmp_path / "auth.jsonl"
    labels = tmp_path / "labels.jsonl"
    output = tmp_path / "observations.jsonl"
    record = _valid_zeek_record()
    flow_key = "192.0.2.1:10000-192.0.2.2:443-tcp"
    write_jsonl(telemetry, [record])
    write_jsonl(auth, [{"window_id": "w1", "failed_auth": 0}])
    write_jsonl(
        labels,
        [
            {
                "window_id": "w1",
                "timestamp": 1.0,
                "flow_keys": [flow_key],
                "label": "benign",
                "split": "train",
                "scenario": "reference",
            }
        ],
    )

    summary = build_observations(telemetry, auth, labels, output)
    assert summary["observation_count"] == 1
    observation = read_jsonl(output)[0]
    assert observation["window_id"] == "w1"
    assert observation["failed_auth"] == 0.0
    assert observation["connection_rate"] == 1.0

    write_jsonl(auth, [{"window_id": "w2", "failed_auth": 0}])
    with pytest.raises(ValueError, match="windows do not match"):
        build_observations(telemetry, auth, labels, output)

    write_jsonl(auth, [{"window_id": "w1", "failed_auth": 0}])
    record["id.orig_p"] = 10001
    write_jsonl(telemetry, [record])
    with pytest.raises(ValueError, match="unknown flow key"):
        build_observations(telemetry, auth, labels, output)
