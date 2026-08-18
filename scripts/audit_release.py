#!/usr/bin/env python3
"""Audit Git history, package archives, evidence assets, and checksums."""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import tarfile
import tomllib
import zipfile
from collections.abc import Iterable
from pathlib import Path, PurePosixPath

PRIVATE_NAMES = {
    "agents.md",
    "claude.md",
    "academic phrasebank.pdf",
    "progress.md",
}
PRIVATE_PATH_WORDS = ("partner-discussion", "proposal", "screenshot")
NON_HUMAN_IDENTIFIERS = ("chatgpt", "openai", "claude", "codex", "copilot")
IGNORED_BUILD_HELPERS = {".gitignore"}
PRIVATE_KEY_BEGIN_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
)
REQUIRED_EVIDENCE_SUFFIXES = {
    "CITATION.cff",
    "LICENSE",
    "NOTICE",
    "TRL3_EVIDENCE.md",
    "trl3/assurance_events.jsonl",
    "trl3/baseline.json",
    "trl3/data/auth.jsonl",
    "trl3/data/labels.jsonl",
    "trl3/data/traffic.pcap",
    "trl3/data/zeek-output/conn.log",
    "trl3/model/model.json",
    "trl3/model/model_manifest.json",
    "trl3/public_key.pem",
    "trl3/run_summary.json",
    "trl3/verification_report.json",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run(repository: Path, *command: str) -> str:
    result = subprocess.run(
        command,
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def _private_path(path: str, *, allow_public_key: bool = False) -> bool:
    pure = PurePosixPath(path)
    lowered = path.casefold()
    key_file = pure.suffix.casefold() in {".key", ".pem"}
    if allow_public_key and pure.name == "public_key.pem":
        key_file = False
    return (
        pure.name.casefold() in PRIVATE_NAMES
        or key_file
        or any(word in lowered for word in PRIVATE_PATH_WORDS)
    )


def audit_history(repository: Path) -> None:
    objects = _run(repository, "git", "rev-list", "--objects", "--all")
    leaked_paths = []
    for line in objects.splitlines():
        _, separator, path = line.partition(" ")
        if separator and _private_path(path):
            leaked_paths.append(path)
    if leaked_paths:
        raise ValueError(f"Private paths found in Git history  {sorted(set(leaked_paths))}")

    identities = _run(
        repository,
        "git",
        "log",
        "--all",
        "--format=%an%x00%ae%x00%cn%x00%ce%x00%(trailers:key=Co-authored-by,valueonly)%x1e",
    ).casefold()
    found = [name for name in NON_HUMAN_IDENTIFIERS if name in identities]
    if found:
        raise ValueError(f"Non-human authorship or contribution metadata found  {found}")


def audit_versions(repository: Path, expected_version: str) -> None:
    project = tomllib.loads((repository / "pyproject.toml").read_text(encoding="utf-8"))
    project_version = str(project["project"]["version"])
    package_text = (repository / "src/veritas_ai/__init__.py").read_text(encoding="utf-8")
    match = re.search(r'^__version__ = "([^"]+)"$', package_text, re.MULTILINE)
    citation = (repository / "CITATION.cff").read_text(encoding="utf-8")
    if project_version != expected_version or match is None or match.group(1) != expected_version:
        raise ValueError("Package versions do not match the expected release version")
    if f"version: {expected_version}" not in citation:
        raise ValueError("CITATION.cff version does not match the package")
    if citation.count("family-names:") != 1 or "family-names: Ahmed" not in citation:
        raise ValueError("CITATION.cff must name Shafiq Ahmed as the sole initial author")


def _audit_member_names(names: Iterable[str], archive: Path) -> set[str]:
    normalised: set[str] = set()
    for name in names:
        pure = PurePosixPath(name)
        if pure.is_absolute() or ".." in pure.parts:
            raise ValueError(f"Unsafe path in {archive.name}  {name}")
        if _private_path(name, allow_public_key=True):
            raise ValueError(f"Private path in {archive.name}  {name}")
        normalised.add(pure.as_posix())
    return normalised


def _check_bytes(content: bytes, description: str) -> None:
    if any(
        marker in content and marker.replace(b"BEGIN", b"END") in content
        for marker in PRIVATE_KEY_BEGIN_MARKERS
    ):
        raise ValueError(f"Private key material found in {description}")


def audit_zip(path: Path) -> set[str]:
    with zipfile.ZipFile(path) as archive:
        names = _audit_member_names(archive.namelist(), path)
        for member in archive.infolist():
            if member.file_size <= 2 * 1024 * 1024:
                _check_bytes(archive.read(member), f"{path.name}/{member.filename}")
        metadata = [name for name in names if name.endswith(".dist-info/METADATA")]
        if len(metadata) != 1:
            raise ValueError(f"Expected one wheel metadata file in {path.name}")
        value = archive.read(metadata[0]).decode("utf-8")
        if "Author-email: Shafiq Ahmed <csshafiqahmed@gmail.com>" not in value:
            raise ValueError("Wheel author metadata does not name Shafiq Ahmed")
    return names


def audit_tar(path: Path) -> set[str]:
    with tarfile.open(path, "r:*") as archive:
        members = [member for member in archive.getmembers() if member.isfile()]
        names = _audit_member_names((member.name for member in members), path)
        for member in members:
            if member.size <= 2 * 1024 * 1024:
                extracted = archive.extractfile(member)
                if extracted is not None:
                    _check_bytes(extracted.read(), f"{path.name}/{member.name}")
    return names


def _release_asset_files(artifacts: Path) -> list[Path]:
    files: list[Path] = []
    for path in artifacts.iterdir():
        if path.name == "SHA256SUMS" or path.name in IGNORED_BUILD_HELPERS:
            continue
        if path.name.startswith("."):
            raise ValueError(f"Unexpected hidden release file  {path.name}")
        if not path.is_file():
            raise ValueError(f"Unexpected release directory  {path.name}")
        files.append(path)
    return sorted(files)


def write_checksums(artifacts: Path) -> Path:
    checksum_path = artifacts / "SHA256SUMS"
    files = _release_asset_files(artifacts)
    if not files:
        raise ValueError("No release assets are available for checksumming")
    checksum_path.write_text(
        "".join(f"{sha256_file(path)}  {path.name}\n" for path in files),
        encoding="utf-8",
    )
    return checksum_path


def audit_checksums(artifacts: Path) -> None:
    checksum_path = artifacts / "SHA256SUMS"
    expected_files = {path.name for path in _release_asset_files(artifacts)}
    recorded: set[str] = set()
    for line in checksum_path.read_text(encoding="utf-8").splitlines():
        digest, separator, name = line.partition("  ")
        if not separator or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError(f"Malformed checksum line  {line}")
        if Path(name).name != name or name in recorded:
            raise ValueError(f"Unsafe or repeated checksum name  {name}")
        path = artifacts / name
        if not path.is_file() or sha256_file(path) != digest:
            raise ValueError(f"Checksum mismatch  {name}")
        recorded.add(name)
    if recorded != expected_files:
        raise ValueError("SHA256SUMS does not cover every release asset exactly once")


def audit_artifacts(artifacts: Path, expected_version: str) -> None:
    wheels = list(artifacts.glob(f"veritas_ai_assurance-{expected_version}-*.whl"))
    sdists = list(artifacts.glob(f"veritas_ai_assurance-{expected_version}.tar.gz"))
    evidence = list(artifacts.glob(f"veritas-ai-{expected_version}-evidence.tar.gz"))
    sboms = list(artifacts.glob(f"veritas-ai-{expected_version}.spdx.json"))
    recordings = list(artifacts.glob(f"veritas-ai-{expected_version}-demo.cast"))
    if any(len(group) != 1 for group in (wheels, sdists, evidence, sboms, recordings)):
        raise ValueError(
            "Release assets must contain one wheel, sdist, evidence bundle, SBOM, and cast"
        )
    audit_zip(wheels[0])
    sdist_names = audit_tar(sdists[0])
    evidence_names = audit_tar(evidence[0])
    if not any(name.endswith("/CITATION.cff") for name in sdist_names):
        raise ValueError("Source distribution does not contain CITATION.cff")
    for suffix in REQUIRED_EVIDENCE_SUFFIXES:
        if not any(name.endswith(f"/{suffix}") for name in evidence_names):
            raise ValueError(f"Evidence bundle is missing {suffix}")
    audit_checksums(artifacts)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--artifacts", type=Path)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--write-checksums", action="store_true")
    args = parser.parse_args()
    repository = args.repository.resolve()
    audit_history(repository)
    audit_versions(repository, args.expected_version)
    if args.artifacts is not None:
        artifacts = args.artifacts.resolve()
        if args.write_checksums:
            write_checksums(artifacts)
        audit_artifacts(artifacts, args.expected_version)
    print("Release audit passed")


if __name__ == "__main__":
    main()
