# Contributing

Contributions should preserve the evidence boundaries and deterministic workflow described in `docs/specification.md`.

## Development

```bash
uv sync --all-groups
uv run ruff check .
uv run ruff format --check .
uv run mypy src/veritas_ai
uv run pytest --cov=veritas_ai --cov-report=term-missing
```

Open an issue before changing public commands, schema version `1.0`, class order, feature order, thresholds, or the TRL claim. Pull requests should state the evidence produced and the limitations that remain.

Do not submit live traffic, personal data, secrets, exploit payloads, private keys, or executable model files.
