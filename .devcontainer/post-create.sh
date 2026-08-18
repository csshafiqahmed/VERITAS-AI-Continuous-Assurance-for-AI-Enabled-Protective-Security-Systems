#!/usr/bin/env bash
set -euo pipefail

readonly VERITAS_UV_VERSION="0.7.17"
readonly VERITAS_UV_INSTALLER="/tmp/uv-installer-${VERITAS_UV_VERSION}.sh"

curl --fail --location --silent --show-error \
  "https://astral.sh/uv/${VERITAS_UV_VERSION}/install.sh" \
  --output "${VERITAS_UV_INSTALLER}"
bash "${VERITAS_UV_INSTALLER}"
/home/vscode/.local/bin/uv sync --all-groups --frozen
