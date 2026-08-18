#!/usr/bin/env python3
"""Build a normalised archive of the verified TRL 3 demonstration evidence."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import tarfile
from pathlib import Path, PurePosixPath

REQUIRED_RUN_PATHS = {
    "assurance_events.jsonl",
    "baseline.json",
    "data/auth.jsonl",
    "data/dataset_manifest.json",
    "data/labels.jsonl",
    "data/observations.jsonl",
    "data/traffic.pcap",
    "data/zeek-output/conn.log",
    "model/model.json",
    "model/model_manifest.json",
    "public_key.pem",
    "run_summary.json",
    "verification_report.json",
}
PRIVATE_KEY_BEGIN_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
)
PUBLIC_FILES = {
    "CITATION.cff": "CITATION.cff",
    "LICENSE": "LICENSE",
    "NOTICE": "NOTICE",
    "docs/trl3-evidence.md": "TRL3_EVIDENCE.md",
}
INTERNAL_RUN_PATHS = frozenset({".guided-state.json"})


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _contains_private_key(path: Path) -> bool:
    carry = b""
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            sample = carry + chunk
            if any(
                marker in sample and marker.replace(b"BEGIN", b"END") in sample
                for marker in PRIVATE_KEY_BEGIN_MARKERS
            ):
                return True
            carry = sample[-64:]
    return False


def _normalised_info(path: Path, archive_name: str) -> tarfile.TarInfo:
    info = tarfile.TarInfo(archive_name)
    info.size = path.stat().st_size
    info.mode = 0o644
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    return info


def _add_file(archive: tarfile.TarFile, path: Path, archive_name: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"Release evidence must be a regular file, found {path}")
    if _contains_private_key(path):
        raise ValueError(f"Private key material detected in {path}")
    with path.open("rb") as handle:
        archive.addfile(_normalised_info(path, archive_name), handle)


def build_bundle(run_dir: Path, output: Path, version: str, repository: Path) -> str:
    run_dir = run_dir.resolve()
    repository = repository.resolve()
    found = {
        PurePosixPath(path.relative_to(run_dir).as_posix()).as_posix()
        for path in run_dir.rglob("*")
        if path.is_file()
    }
    missing = sorted(REQUIRED_RUN_PATHS - found)
    if missing:
        raise ValueError(f"Demonstration evidence is incomplete, missing {', '.join(missing)}")

    release_paths: list[Path] = []
    for path in sorted(run_dir.rglob("*")):
        if not path.is_file():
            continue
        relative = PurePosixPath(path.relative_to(run_dir).as_posix())
        if relative.as_posix() in INTERNAL_RUN_PATHS:
            continue
        if any(part.startswith(".") for part in relative.parts):
            raise ValueError(f"Unexpected hidden run file {relative}")
        release_paths.append(path)

    output.parent.mkdir(parents=True, exist_ok=True)
    prefix = f"veritas-ai-{version}-evidence"
    with (
        output.open("wb") as raw_output,
        gzip.GzipFile(filename="", mode="wb", fileobj=raw_output, mtime=0) as compressed,
        tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive,
    ):
        for source_name, target_name in sorted(PUBLIC_FILES.items()):
            _add_file(archive, repository / source_name, f"{prefix}/{target_name}")
        for path in release_paths:
            relative = path.relative_to(run_dir).as_posix()
            _add_file(archive, path, f"{prefix}/trl3/{relative}")
    return sha256_file(output)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    args = parser.parse_args()
    digest = build_bundle(args.run_dir, args.output, args.version, args.repository)
    print(f"{digest}  {args.output.name}")


if __name__ == "__main__":
    main()
