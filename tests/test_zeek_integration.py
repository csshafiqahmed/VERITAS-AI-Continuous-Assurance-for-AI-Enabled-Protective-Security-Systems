import os
from pathlib import Path

import pytest

from veritas_ai.constants import ZEEK_IMAGE, ZEEK_VERSION
from veritas_ai.data import validate_zeek_conn_log
from veritas_ai.io import read_json


@pytest.mark.zeek
def test_pinned_zeek_evidence_from_cli() -> None:
    run_value = os.environ.get("VERITAS_ZEEK_RUN")
    if run_value is None:
        pytest.skip("Set VERITAS_ZEEK_RUN after running the Docker-backed demonstration")

    run_dir = Path(run_value)
    summary = read_json(run_dir / "run_summary.json")
    manifest = summary["dataset_manifest"]
    conn_log = run_dir / "data/zeek-output/conn.log"

    assert manifest["zeek_mode"] == "official_container"
    assert manifest["zeek"]["image"] == ZEEK_IMAGE
    assert ZEEK_VERSION in manifest["zeek"]["version"]
    assert manifest["zeek"]["network_access"] == "disabled"
    assert manifest["zeek"]["record_count"] == manifest["observation_count"]
    assert validate_zeek_conn_log(conn_log, manifest["observation_count"])["record_count"] == 5000
    assert summary["ledger_valid"] is True
