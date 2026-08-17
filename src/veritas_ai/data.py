"""Deterministic safe telemetry generation and Zeek integration."""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Any

import dpkt
import numpy as np

from veritas_ai.constants import CLASSES, DEFAULT_SEED, SCHEMA_VERSION
from veritas_ai.io import sha256_file, write_json, write_jsonl

SCENARIOS = [
    "stable_operation",
    "benign_workload_change",
    "partial_telemetry_loss",
    "gradual_feature_drift",
    "model_replacement",
    "recovery_after_investigation",
]


def _split_and_scenario(index: int) -> tuple[str, str]:
    if index < 2500:
        return "train", "reference"
    if index < 3000:
        return "calibration", "reference"
    if index < 3500:
        return "baseline", "reference"
    scenario_index = min((index - 3500) // 250, len(SCENARIOS) - 1)
    return "monitor", SCENARIOS[scenario_index]


def _class_features(label: str, rng: np.random.Generator) -> dict[str, float]:
    base: dict[str, tuple[float, float]] = {
        "benign": (220.0, 180.0),
        "authentication_abuse": (120.0, 90.0),
        "reconnaissance": (70.0, 35.0),
        "lateral_movement": (420.0, 260.0),
        "abnormal_data_transfer": (1900.0, 320.0),
    }
    orig_mean, resp_mean = base[label]
    features = {
        "duration": float(max(0.01, rng.lognormal(0.0, 0.55))),
        "orig_bytes": float(max(1.0, rng.normal(orig_mean, orig_mean * 0.12))),
        "resp_bytes": float(max(1.0, rng.normal(resp_mean, resp_mean * 0.12))),
        "orig_pkts": float(max(1, round(rng.normal(4, 1)))),
        "resp_pkts": float(max(1, round(rng.normal(3, 1)))),
        "unique_destinations": float(max(1, round(rng.normal(3, 1)))),
        "failed_auth": 0.0,
        "new_service_ratio": float(np.clip(rng.normal(0.08, 0.03), 0, 1)),
        "connection_rate": float(max(0.1, rng.normal(4.0, 0.8))),
        "telemetry_missing": 0.0,
    }
    if label == "authentication_abuse":
        features["failed_auth"] = float(rng.integers(8, 25))
        features["connection_rate"] += 4
    elif label == "reconnaissance":
        features["unique_destinations"] = float(rng.integers(18, 45))
        features["new_service_ratio"] = float(rng.uniform(0.55, 0.95))
        features["connection_rate"] += 12
    elif label == "lateral_movement":
        features["unique_destinations"] = float(rng.integers(8, 18))
        features["failed_auth"] = float(rng.integers(1, 7))
        features["new_service_ratio"] = float(rng.uniform(0.30, 0.65))
    elif label == "abnormal_data_transfer":
        features["orig_bytes"] *= 4
        features["duration"] *= 3
    return features


def _packet(
    source: str,
    destination: str,
    source_port: int,
    destination_port: int,
    payload_size: int,
    reverse: bool = False,
) -> bytes:
    payload = b"V" * min(max(payload_size, 1), 1200)
    tcp = dpkt.tcp.TCP(
        sport=destination_port if reverse else source_port,
        dport=source_port if reverse else destination_port,
        seq=1,
        flags=dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH,
        data=payload,
    )
    src = destination if reverse else source
    dst = source if reverse else destination
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst), p=dpkt.ip.IP_PROTO_TCP)
    ip.data = tcp
    ip.len = len(ip)
    ethernet = dpkt.ethernet.Ethernet(
        src=b"\x02\x00\x00\x00\x00\x01",
        dst=b"\x02\x00\x00\x00\x00\x02",
        type=dpkt.ethernet.ETH_TYPE_IP,
        data=ip,
    )
    return bytes(ethernet)


def generate_dataset(output: Path, count: int = 5000, seed: int = DEFAULT_SEED) -> dict[str, Any]:
    """Generate safe labelled observations, auth events, labels, PCAP, and Zeek-compatible JSON."""
    output.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(seed)
    observations: list[dict[str, Any]] = []
    auth_events: list[dict[str, Any]] = []
    labels: list[dict[str, Any]] = []
    zeek_records: list[dict[str, Any]] = []
    epoch = 1_700_000_000.0
    pcap_path = output / "traffic.pcap"

    with pcap_path.open("wb") as handle:
        writer = dpkt.pcap.Writer(handle)
        for index in range(count):
            split, scenario = _split_and_scenario(index)
            label = str(rng.choice(CLASSES, p=[0.60, 0.10, 0.10, 0.10, 0.10]))
            features = _class_features(label, rng)
            if scenario == "benign_workload_change":
                features["connection_rate"] *= 1.18
            elif scenario == "partial_telemetry_loss":
                features["telemetry_missing"] = 1.0 if index % 10 == 0 else 0.0
            elif scenario == "gradual_feature_drift":
                progress = ((index - 4250) % 250) / 249
                features["orig_bytes"] *= 1 + progress * 2.0
                features["unique_destinations"] += progress * 18

            source = f"10.{(index // 60000) % 250}.{(index // 250) % 250}.{index % 250 + 1}"
            destination = f"192.0.2.{index % 250 + 1}"
            source_port = 10000 + index
            destination_port = [22, 80, 443, 445, 3389][index % 5]
            flow_key = f"{source}:{source_port}-{destination}:{destination_port}-tcp"
            timestamp = epoch + index * 2
            window_id = f"w{index:06d}"
            record: dict[str, Any] = {
                "schema_version": SCHEMA_VERSION,
                "window_id": window_id,
                "timestamp": timestamp,
                "flow_key": flow_key,
                "split": split,
                "scenario": scenario,
                "label": label,
                **features,
            }
            observations.append(record)
            auth_events.append(
                {
                    "schema_version": SCHEMA_VERSION,
                    "window_id": window_id,
                    "timestamp": timestamp,
                    "failed_auth": int(features["failed_auth"]),
                    "synthetic": True,
                }
            )
            labels.append(
                {
                    "schema_version": SCHEMA_VERSION,
                    "window_id": window_id,
                    "flow_key": flow_key,
                    "label": label,
                    "split": split,
                    "scenario": scenario,
                }
            )
            zeek_records.append(
                {
                    "ts": timestamp,
                    "uid": window_id,
                    "id.orig_h": source,
                    "id.orig_p": source_port,
                    "id.resp_h": destination,
                    "id.resp_p": destination_port,
                    "proto": "tcp",
                    "duration": features["duration"],
                    "orig_bytes": int(features["orig_bytes"]),
                    "resp_bytes": int(features["resp_bytes"]),
                    "orig_pkts": int(features["orig_pkts"]),
                    "resp_pkts": int(features["resp_pkts"]),
                    "synthetic_zeek_compatible": True,
                }
            )
            writer.writepkt(
                _packet(
                    source, destination, source_port, destination_port, int(features["orig_bytes"])
                ),
                ts=timestamp,
            )
            writer.writepkt(
                _packet(
                    source,
                    destination,
                    source_port,
                    destination_port,
                    int(features["resp_bytes"]),
                    True,
                ),
                ts=timestamp + min(features["duration"], 1.0),
            )

    write_jsonl(output / "observations.jsonl", observations)
    write_jsonl(output / "auth.jsonl", auth_events)
    write_jsonl(output / "labels.jsonl", labels)
    write_jsonl(output / "conn.log", zeek_records)
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "seed": seed,
        "observation_count": count,
        "classes": CLASSES,
        "traffic_mode": "safe_synthetic",
        "zeek_mode": "synthetic_zeek_compatible",
        "files": {
            name: sha256_file(output / name)
            for name in [
                "traffic.pcap",
                "observations.jsonl",
                "auth.jsonl",
                "labels.jsonl",
                "conn.log",
            ]
        },
    }
    write_json(output / "dataset_manifest.json", manifest)
    return manifest


def process_with_zeek(data_dir: Path, image: str) -> Path:
    """Process the generated PCAP with a pinned Zeek container."""
    if shutil.which("docker") is None:
        raise RuntimeError("Docker is required for --regenerate-zeek")
    zeek_output = data_dir / "zeek-output"
    zeek_output.mkdir(parents=True, exist_ok=True)
    command = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{data_dir.resolve()}:/input:ro",
        "-v",
        f"{zeek_output.resolve()}:/output",
        "-w",
        "/output",
        image,
        "zeek",
        "-Cr",
        "/input/traffic.pcap",
        "LogAscii::use_json=T",
    ]
    subprocess.run(command, check=True)
    conn_log = zeek_output / "conn.log"
    if not conn_log.exists():
        raise RuntimeError("Zeek did not produce conn.log")
    manifest_path = data_dir / "dataset_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["zeek_mode"] = "official_container"
    manifest["files"]["zeek-output/conn.log"] = sha256_file(conn_log)
    write_json(manifest_path, manifest)
    return conn_log
