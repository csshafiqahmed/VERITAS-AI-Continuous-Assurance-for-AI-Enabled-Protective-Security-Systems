"""Deterministic safe telemetry generation and Zeek integration."""

from __future__ import annotations

import os
import re
import secrets
import shutil
import socket
import subprocess
from collections import Counter, defaultdict
from collections.abc import Callable
from pathlib import Path
from typing import Any

import dpkt
import numpy as np

from veritas_ai.constants import CLASSES, DEFAULT_SEED, SCHEMA_VERSION, ZEEK_VERSION
from veritas_ai.io import (
    canonical_json,
    read_json,
    read_jsonl,
    sha256_file,
    write_json,
    write_jsonl,
)

SCENARIOS = [
    "stable_operation",
    "benign_workload_change",
    "partial_telemetry_loss",
    "gradual_feature_drift",
    "model_replacement",
    "recovery_after_investigation",
]

KNOWN_SERVICE_PORTS = (22, 53, 80, 443, 445, 3389)
WINDOW_SECONDS = 10.0

ZEEK_REQUIRED_FIELDS = frozenset(
    {
        "ts",
        "uid",
        "id.orig_h",
        "id.orig_p",
        "id.resp_h",
        "id.resp_p",
        "proto",
        "duration",
        "orig_bytes",
        "resp_bytes",
        "orig_pkts",
        "resp_pkts",
    }
)
_PINNED_ZEEK_IMAGE = re.compile(
    r"zeek/zeek:\d+\.\d+\.\d+@sha256:[0-9a-f]{64}",
    flags=re.ASCII,
)


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
    sequence: int = 1,
    reverse: bool = False,
) -> bytes:
    payload = b"V" * max(payload_size, 1)
    tcp = dpkt.tcp.TCP(
        sport=destination_port if reverse else source_port,
        dport=source_port if reverse else destination_port,
        seq=sequence,
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


def _flow_key(record: dict[str, Any]) -> str:
    try:
        source = str(record["id.orig_h"])
        source_port = int(record["id.orig_p"])
        destination = str(record["id.resp_h"])
        destination_port = int(record["id.resp_p"])
        protocol = str(record["proto"])
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("Connection record has an invalid flow identifier") from error
    return f"{source}:{source_port}-{destination}:{destination_port}-{protocol}"


def _payload_chunks(total: int, count: int) -> list[int]:
    quotient, remainder = divmod(max(total, count), count)
    return [quotient + (1 if index < remainder else 0) for index in range(count)]


def build_observations(
    telemetry_path: Path,
    auth_path: Path,
    labels_path: Path,
    output_path: Path,
) -> dict[str, Any]:
    """Join connection, authentication, and label evidence into stable observation windows."""
    connections = read_jsonl(telemetry_path)
    auth_events = read_jsonl(auth_path)
    labels = read_jsonl(labels_path)
    if not connections or not auth_events or not labels:
        raise ValueError("Feature building requires telemetry, authentication events, and labels")

    label_by_window: dict[str, dict[str, Any]] = {}
    flow_to_window: dict[str, str] = {}
    for label_record in labels:
        window_id = str(label_record.get("window_id", ""))
        if not window_id or window_id in label_by_window:
            raise ValueError("Labels require unique non-empty window identifiers")
        flow_keys = label_record.get("flow_keys")
        if not isinstance(flow_keys, list) or not flow_keys:
            raise ValueError(f"Label window {window_id} requires at least one flow key")
        for value in flow_keys:
            flow_key = str(value)
            if flow_key in flow_to_window:
                raise ValueError(f"Flow key {flow_key} is assigned to more than one window")
            flow_to_window[flow_key] = window_id
        label_by_window[window_id] = label_record

    auth_by_window: dict[str, dict[str, Any]] = {}
    for auth_record in auth_events:
        window_id = str(auth_record.get("window_id", ""))
        if not window_id or window_id in auth_by_window:
            raise ValueError("Authentication events require unique non-empty window identifiers")
        auth_by_window[window_id] = auth_record
    if set(auth_by_window) != set(label_by_window):
        raise ValueError("Authentication and label windows do not match")

    grouped: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    seen_flows: set[str] = set()
    for connection in connections:
        flow_key = _flow_key(connection)
        if flow_key in seen_flows:
            raise ValueError(f"Connection telemetry repeats flow key {flow_key}")
        seen_flows.add(flow_key)
        mapped_window = flow_to_window.get(flow_key)
        if mapped_window is None:
            raise ValueError(f"Connection telemetry contains unknown flow key {flow_key}")
        grouped[mapped_window].append(connection)
    missing_flows = sorted(set(flow_to_window).difference(seen_flows))
    if missing_flows:
        raise ValueError(f"Connection telemetry is missing {len(missing_flows)} expected flows")

    observations: list[dict[str, Any]] = []
    for window_id in sorted(label_by_window):
        label_record = label_by_window[window_id]
        auth_record = auth_by_window[window_id]
        window_connections = grouped[window_id]
        responder_ports = [int(record["id.resp_p"]) for record in window_connections]
        observations.append(
            {
                "schema_version": SCHEMA_VERSION,
                "window_id": window_id,
                "timestamp": float(label_record["timestamp"]),
                "split": str(label_record["split"]),
                "scenario": str(label_record["scenario"]),
                "label": str(label_record["label"]),
                "duration": float(
                    np.mean([float(record["duration"]) for record in window_connections])
                ),
                "orig_bytes": float(
                    np.mean([float(record["orig_bytes"]) for record in window_connections])
                ),
                "resp_bytes": float(
                    np.mean([float(record["resp_bytes"]) for record in window_connections])
                ),
                "orig_pkts": float(
                    np.mean([float(record["orig_pkts"]) for record in window_connections])
                ),
                "resp_pkts": float(
                    np.mean([float(record["resp_pkts"]) for record in window_connections])
                ),
                "unique_destinations": float(
                    len({str(record["id.resp_h"]) for record in window_connections})
                ),
                "failed_auth": float(auth_record["failed_auth"]),
                "new_service_ratio": float(
                    np.mean(
                        [port not in KNOWN_SERVICE_PORTS for port in responder_ports],
                    )
                ),
                "connection_rate": float(len(window_connections)),
                "telemetry_missing": float(auth_record.get("telemetry_missing", 0.0)),
            }
        )

    write_jsonl(output_path, observations)
    return {
        "schema_version": SCHEMA_VERSION,
        "window_strategy": "explicit_flow_to_window_mapping",
        "window_seconds": WINDOW_SECONDS,
        "observation_count": len(observations),
        "connection_count": len(connections),
        "authentication_event_count": len(auth_events),
        "label_count": len(labels),
        "output_sha256": sha256_file(output_path),
    }


def attach_ground_truth(records: list[dict[str, Any]], labels_path: Path) -> list[dict[str, Any]]:
    """Attach explicit ground truth to observation windows without using row order."""
    labels_by_window: dict[str, str] = {}
    for label_record in read_jsonl(labels_path):
        window_id = str(label_record.get("window_id", ""))
        label = str(label_record.get("label", ""))
        if not window_id or window_id in labels_by_window:
            raise ValueError("Ground truth requires unique non-empty window identifiers")
        if label not in CLASSES:
            raise ValueError(f"Ground truth for {window_id} has an unknown class")
        labels_by_window[window_id] = label

    joined: list[dict[str, Any]] = []
    seen_windows: set[str] = set()
    for record in records:
        window_id = str(record.get("window_id", ""))
        if not window_id or window_id in seen_windows:
            raise ValueError("Monitoring records require unique non-empty window identifiers")
        seen_windows.add(window_id)
        mapped_label = labels_by_window.get(window_id)
        if mapped_label is None:
            raise ValueError(f"Ground truth is unavailable for monitoring window {window_id}")
        joined.append({**record, "label": mapped_label})
    return joined


def generate_dataset(
    output: Path,
    count: int = 5000,
    seed: int = DEFAULT_SEED,
    progress: Callable[[int, int], None] | None = None,
) -> dict[str, Any]:
    """Generate safe labelled observations, auth events, labels, PCAP, and Zeek-compatible JSON."""
    output.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(seed)
    auth_events: list[dict[str, Any]] = []
    labels: list[dict[str, Any]] = []
    zeek_records: list[dict[str, Any]] = []
    recovery_templates: list[tuple[str, dict[str, float]]] = []
    epoch = 1_700_000_000.0
    pcap_path = output / "traffic.pcap"

    with pcap_path.open("wb") as handle:
        writer = dpkt.pcap.Writer(handle, snaplen=65535)
        for index in range(count):
            split, scenario = _split_and_scenario(index)
            if scenario == "recovery_after_investigation":
                if len(recovery_templates) != 500:
                    raise ValueError("Recovery generation requires all 500 baseline templates")
                recovery_offset = (index - 4750) % 250
                template_lane = 0 if recovery_offset < 125 else 1
                template_index = template_lane + 4 * (recovery_offset % 125)
                label, template = recovery_templates[template_index]
                features = dict(template)
            else:
                label = str(rng.choice(CLASSES, p=[0.60, 0.10, 0.10, 0.10, 0.10]))
                features = _class_features(label, rng)
                if scenario == "benign_workload_change":
                    features["connection_rate"] *= 1.18
                elif scenario == "partial_telemetry_loss":
                    features["telemetry_missing"] = 1.0 if index % 10 == 0 else 0.0
                elif scenario == "gradual_feature_drift":
                    drift_progress = ((index - 4250) % 250) / 249
                    features["resp_pkts"] += drift_progress * 4
                if split == "baseline":
                    recovery_templates.append((label, dict(features)))

            source = f"10.{(index // 60000) % 250}.{(index // 250) % 250}.{index % 250 + 1}"
            timestamp = epoch + index * WINDOW_SECONDS
            window_id = f"w{index:06d}"
            flow_count = max(
                1,
                round(features["connection_rate"]),
                round(features["unique_destinations"]),
            )
            unique_destination_count = min(
                flow_count,
                max(1, round(features["unique_destinations"])),
            )
            new_service_count = min(
                flow_count,
                max(0, round(features["new_service_ratio"] * flow_count)),
            )
            response_packet_count = max(1, round(features["resp_pkts"]))
            duration = min(max(0.01, features["duration"]), WINDOW_SECONDS * 0.8)
            orig_bytes = max(1, round(features["orig_bytes"]))
            resp_bytes = max(1, round(features["resp_bytes"]))
            flow_keys: list[str] = []
            packet_events: list[tuple[float, bytes]] = []

            for flow_index in range(flow_count):
                destination = f"192.0.2.{flow_index % unique_destination_count + 1}"
                source_port = 10000 + flow_index
                destination_port = (
                    8000 + flow_index
                    if flow_index < new_service_count
                    else KNOWN_SERVICE_PORTS[(index + flow_index) % len(KNOWN_SERVICE_PORTS)]
                )
                flow_key = f"{source}:{source_port}-{destination}:{destination_port}-tcp"
                flow_keys.append(flow_key)
                flow_timestamp = timestamp + flow_index * 0.001
                zeek_records.append(
                    {
                        "ts": flow_timestamp,
                        "uid": f"{window_id}-{flow_index:03d}",
                        "id.orig_h": source,
                        "id.orig_p": source_port,
                        "id.resp_h": destination,
                        "id.resp_p": destination_port,
                        "proto": "tcp",
                        "duration": duration,
                        "orig_bytes": orig_bytes,
                        "resp_bytes": resp_bytes,
                        "orig_pkts": 1,
                        "resp_pkts": response_packet_count,
                        "synthetic_zeek_compatible": True,
                    }
                )
                packet_events.append(
                    (
                        flow_timestamp,
                        _packet(
                            source,
                            destination,
                            source_port,
                            destination_port,
                            orig_bytes,
                        ),
                    )
                )
                sequence = 1
                for packet_index, payload_size in enumerate(
                    _payload_chunks(resp_bytes, response_packet_count), start=1
                ):
                    packet_events.append(
                        (
                            flow_timestamp + duration * packet_index / response_packet_count,
                            _packet(
                                source,
                                destination,
                                source_port,
                                destination_port,
                                payload_size,
                                sequence=sequence,
                                reverse=True,
                            ),
                        )
                    )
                    sequence += payload_size

            for packet_timestamp, packet in sorted(packet_events, key=lambda event: event[0]):
                writer.writepkt(packet, ts=packet_timestamp)

            auth_events.append(
                {
                    "schema_version": SCHEMA_VERSION,
                    "window_id": window_id,
                    "timestamp": timestamp,
                    "failed_auth": int(features["failed_auth"]),
                    "telemetry_missing": float(features["telemetry_missing"]),
                    "synthetic": True,
                }
            )
            labels.append(
                {
                    "schema_version": SCHEMA_VERSION,
                    "window_id": window_id,
                    "timestamp": timestamp,
                    "flow_keys": flow_keys,
                    "label": label,
                    "split": split,
                    "scenario": scenario,
                }
            )
            completed = index + 1
            if progress is not None and (completed % 250 == 0 or completed == count):
                progress(completed, count)

    write_jsonl(output / "auth.jsonl", auth_events)
    write_jsonl(output / "labels.jsonl", labels)
    write_jsonl(output / "conn.log", zeek_records)
    feature_builder = build_observations(
        output / "conn.log",
        output / "auth.jsonl",
        output / "labels.jsonl",
        output / "observations.jsonl",
    )
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "seed": seed,
        "observation_count": count,
        "connection_count": len(zeek_records),
        "classes": CLASSES,
        "traffic_mode": "safe_synthetic",
        "zeek_mode": "synthetic_zeek_compatible",
        "feature_builder": feature_builder,
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


def validate_zeek_conn_log(conn_log: Path, expected_records: int | None = None) -> dict[str, Any]:
    """Validate a JSON Zeek connection log and return bounded provenance."""
    records = read_jsonl(conn_log)
    if not records:
        raise ValueError("Zeek conn.log is empty")
    if expected_records is not None and len(records) != expected_records:
        raise ValueError(
            f"Zeek conn.log contains {len(records)} records, expected {expected_records}"
        )

    timestamps: list[float] = []
    protocols: Counter[str] = Counter()
    for index, record in enumerate(records, start=1):
        missing = sorted(ZEEK_REQUIRED_FIELDS.difference(record))
        if missing:
            raise ValueError(f"Zeek conn.log record {index} is missing {', '.join(missing)}")
        canonical_json(record)
        timestamp = record["ts"]
        if isinstance(timestamp, bool) or not isinstance(timestamp, (int, float)):
            raise ValueError(f"Zeek conn.log record {index} has an invalid timestamp")
        protocol = record["proto"]
        if not isinstance(protocol, str) or not protocol:
            raise ValueError(f"Zeek conn.log record {index} has an invalid protocol")
        timestamps.append(float(timestamp))
        protocols[protocol] += 1

    return {
        "record_count": len(records),
        "first_timestamp": min(timestamps),
        "last_timestamp": max(timestamps),
        "protocol_counts": dict(sorted(protocols.items())),
        "required_fields": sorted(ZEEK_REQUIRED_FIELDS),
    }


def _docker_isolation_arguments(*, remove: bool = True) -> list[str]:
    arguments = [
        "--network",
        "none",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=64m",
        "--user",
        f"{os.getuid()}:{os.getgid()}",
    ]
    if remove:
        arguments.insert(0, "--rm")
    return arguments


def process_with_zeek(data_dir: Path, image: str) -> dict[str, Any]:
    """Process the generated PCAP with an immutable official Zeek container."""
    if _PINNED_ZEEK_IMAGE.fullmatch(image) is None:
        raise ValueError(
            "Zeek image must use the official repository, a patch tag, and a SHA-256 digest"
        )
    if shutil.which("docker") is None:
        raise RuntimeError("Docker is required for --regenerate-zeek")

    version_command = [
        "docker",
        "run",
        *_docker_isolation_arguments(),
        "--entrypoint",
        "zeek",
        image,
        "--version",
    ]
    version_result = subprocess.run(
        version_command,
        check=True,
        capture_output=True,
        text=True,
    )
    version_output = (version_result.stdout or version_result.stderr).strip()
    if ZEEK_VERSION not in version_output:
        raise RuntimeError(
            f"Pinned container reported an unexpected Zeek version, {version_output}"
        )

    zeek_output = data_dir / "zeek-output"
    zeek_output.mkdir(parents=True, exist_ok=True)
    conn_log = zeek_output / "conn.log"
    object_token = secrets.token_hex(8)
    input_volume = f"veritas-ai-zeek-input-{object_token}"
    output_volume = f"veritas-ai-zeek-output-{object_token}"
    staging_container = f"veritas-ai-zeek-stage-{object_token}"
    zeek_container = f"veritas-ai-zeek-run-{object_token}"
    created_containers: list[str] = []
    created_volumes: list[str] = []
    cleanup_failures: list[str] = []

    try:
        for volume in (input_volume, output_volume):
            subprocess.run(
                ["docker", "volume", "create", volume],
                check=True,
                capture_output=True,
                text=True,
            )
            created_volumes.append(volume)

        staging_command = [
            "docker",
            "create",
            "--name",
            staging_container,
            "--network",
            "none",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--read-only",
            "--mount",
            f"type=volume,source={input_volume},target=/input,volume-nocopy",
            "--entrypoint",
            "/bin/true",
            image,
        ]
        subprocess.run(staging_command, check=True, capture_output=True, text=True)
        created_containers.append(staging_container)
        subprocess.run(
            [
                "docker",
                "cp",
                str((data_dir / "traffic.pcap").resolve()),
                f"{staging_container}:/input/traffic.pcap",
            ],
            check=True,
            capture_output=True,
            text=True,
        )

        subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "--cap-drop",
                "ALL",
                "--cap-add",
                "CHOWN",
                "--security-opt",
                "no-new-privileges:true",
                "--read-only",
                "--user",
                "0:0",
                "--mount",
                f"type=volume,source={output_volume},target=/output,volume-nocopy",
                "--entrypoint",
                "chown",
                image,
                f"{os.getuid()}:{os.getgid()}",
                "/output",
            ],
            check=True,
            capture_output=True,
            text=True,
        )

        command = [
            "docker",
            "create",
            "--name",
            zeek_container,
            *_docker_isolation_arguments(remove=False),
            "--mount",
            f"type=volume,source={input_volume},target=/input,readonly,volume-nocopy",
            "--mount",
            f"type=volume,source={output_volume},target=/output,volume-nocopy",
            "--workdir",
            "/output",
            "--entrypoint",
            "zeek",
            image,
            "-Cr",
            "/input/traffic.pcap",
            "LogAscii::use_json=T",
        ]
        subprocess.run(command, check=True, capture_output=True, text=True)
        created_containers.append(zeek_container)
        subprocess.run(
            ["docker", "start", "--attach", zeek_container],
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            [
                "docker",
                "cp",
                f"{zeek_container}:/output/conn.log",
                str(conn_log.resolve()),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
    finally:
        for container in reversed(created_containers):
            cleanup = subprocess.run(
                ["docker", "rm", "--force", container],
                check=False,
                capture_output=True,
                text=True,
            )
            if cleanup.returncode != 0:
                cleanup_failures.append(container)
        for volume in reversed(created_volumes):
            cleanup = subprocess.run(
                ["docker", "volume", "rm", "--force", volume],
                check=False,
                capture_output=True,
                text=True,
            )
            if cleanup.returncode != 0:
                cleanup_failures.append(volume)

    if cleanup_failures:
        raise RuntimeError("Docker cleanup failed for " + ", ".join(sorted(cleanup_failures)))
    if not conn_log.exists():
        raise RuntimeError("Zeek did not produce conn.log")

    manifest_path = data_dir / "dataset_manifest.json"
    manifest = read_json(manifest_path)
    validation = validate_zeek_conn_log(conn_log, int(manifest["connection_count"]))
    feature_builder = build_observations(
        conn_log,
        data_dir / "auth.jsonl",
        data_dir / "labels.jsonl",
        data_dir / "observations.jsonl",
    )
    manifest["zeek_mode"] = "official_container"
    manifest["feature_builder"] = feature_builder
    manifest["zeek"] = {
        "image": image,
        "version": version_output,
        "network_access": "disabled",
        "container_privileges": "all_capabilities_dropped",
        "container_root_filesystem": "read_only",
        "pcap_mount": "read_only",
        "pcap_transport": "docker_cp_with_managed_volumes",
        "transport_preparation_capability": "CHOWN_only",
        **validation,
    }
    manifest["files"]["zeek-output/conn.log"] = sha256_file(conn_log)
    manifest["files"]["observations.jsonl"] = sha256_file(data_dir / "observations.jsonl")
    write_json(manifest_path, manifest)
    return manifest
