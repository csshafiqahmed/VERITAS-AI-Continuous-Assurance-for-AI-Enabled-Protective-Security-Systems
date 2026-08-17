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

Use `--regenerate-zeek` inside the supplied Codespace or another Docker-enabled environment to replace the Zeek-compatible fixture with output from the pinned official container.
