import json
import tarfile
from pathlib import Path

import pytest

from scripts.audit_release import audit_checksums, write_checksums
from scripts.build_demo_cast import build_cast
from scripts.build_evidence_bundle import REQUIRED_RUN_PATHS, build_bundle


def _complete_run(path: Path) -> None:
    for relative in REQUIRED_RUN_PATHS:
        target = path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"public demonstration evidence\n")


def test_evidence_bundle_is_normalised(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    _complete_run(run_dir)
    output = tmp_path / "veritas-ai-0.1.0-evidence.tar.gz"
    build_bundle(run_dir, output, "0.1.0", Path.cwd())

    with tarfile.open(output, "r:gz") as archive:
        members = [member for member in archive.getmembers() if member.isfile()]
    assert members
    assert all(member.mtime == 0 for member in members)
    assert all(member.uid == 0 and member.gid == 0 for member in members)
    assert any(member.name.endswith("/trl3/public_key.pem") for member in members)


def test_evidence_bundle_rejects_private_key(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    _complete_run(run_dir)
    begin_marker = b"-----BEGIN " + b"PRIVATE KEY-----"
    end_marker = b"-----END " + b"PRIVATE KEY-----"
    (run_dir / "baseline.json").write_bytes(begin_marker + b"\nsecret\n" + end_marker + b"\n")
    with pytest.raises(ValueError, match="Private key material"):
        build_bundle(run_dir, tmp_path / "evidence.tar.gz", "0.1.0", Path.cwd())


def test_demo_cast_uses_verified_values(tmp_path: Path) -> None:
    summary = tmp_path / "run_summary.json"
    verification = tmp_path / "verification_report.json"
    output = tmp_path / "demo.cast"
    summary.write_text(
        json.dumps(
            {
                "dataset_manifest": {"observation_count": 5000, "connection_count": 41248},
                "scenario_actions": {"stable_operation": "continue"},
            }
        ),
        encoding="utf-8",
    )
    verification.write_text(
        json.dumps({"valid": True, "events_checked": 6}),
        encoding="utf-8",
    )
    build_cast(summary, verification, output)

    records = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert records[0]["version"] == 2
    rendered = "".join(record[2] for record in records[1:])
    assert "5000 windows" in rendered
    assert "stable_operation" in rendered
    assert "Ledger valid  True" in rendered


def test_checksums_cover_each_asset_once(tmp_path: Path) -> None:
    (tmp_path / "one.whl").write_bytes(b"one")
    (tmp_path / "two.tar.gz").write_bytes(b"two")
    (tmp_path / ".gitignore").write_text("*\n", encoding="utf-8")
    write_checksums(tmp_path)
    audit_checksums(tmp_path)
    assert ".gitignore" not in (tmp_path / "SHA256SUMS").read_text(encoding="utf-8")


def test_checksums_reject_unexpected_hidden_file(tmp_path: Path) -> None:
    (tmp_path / "one.whl").write_bytes(b"one")
    (tmp_path / ".secret").write_bytes(b"not public")
    with pytest.raises(ValueError, match="Unexpected hidden release file"):
        write_checksums(tmp_path)


def test_release_workflow_checks_anonymous_container_access() -> None:
    workflow = Path(".github/workflows/release.yml").read_text(encoding="utf-8")
    assert "/user/packages" not in workflow
    assert "Verify anonymous multi-platform container access" in workflow
    assert "DOCKER_CONFIG" in workflow
    assert "docker buildx imagetools inspect" in workflow
    assert "linux/amd64" in workflow
    assert "linux/arm64" in workflow
