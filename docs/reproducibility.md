# Reproducibility

The demonstration is intended to run from a clean Python 3.12 environment. The dependency lock, fixed seed, native model format, and artifact hashes reduce avoidable variation.

```bash
uv sync --all-groups --frozen
uv run veritas-ai demo --output runs/trl3
uv run veritas-ai verify \
  --ledger runs/trl3/assurance_events.jsonl \
  --public-key runs/trl3/public_key.pem
```

The generated dataset should have identical hashes for the same release, dependency lock, and seed. Model inference is configured with one worker to reduce nondeterminism. Timestamps, ephemeral keys, signatures, and their dependent artifact hashes are expected to change between complete runs.

Use `--regenerate-zeek` inside the supplied Codespace or another Docker-enabled environment to create independent network evidence from the PCAP. The command uses the [official Zeek 8.0.9 LTS image](https://zeek.org/get-zeek/) and pins the Docker Hub multi-platform index `sha256:b705c8932220e5e9e7af3e6519c8b41188aa190066e456f16ab6cfb7d97b760d`.

The container runs without network access or Linux capabilities and with a read-only root filesystem. VERITAS-AI checks the reported Zeek version, parses every JSON record, rejects missing required fields and non-finite values, verifies the expected 5,000-record count, and records the raw log hash in `dataset_manifest.json`. The [Zeek documentation](https://docs.zeek.org/en/v8.0.9/install.html) identifies `zeek/zeek` as the project's official Docker repository. The [Zeek logging guide](https://docs.zeek.org/en/v8.0.9/quickstart.html) documents the JSON `conn.log` invocation used here.
