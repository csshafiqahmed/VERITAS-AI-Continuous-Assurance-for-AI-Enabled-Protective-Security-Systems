FROM python:3.12-slim@sha256:2c941e860699f878900b0edc2403613c234d4b32eda3cc9fa7036991a2a63c4a AS runtime

ARG VERSION=0.2.0
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown

LABEL org.opencontainers.image.title="VERITAS-AI" \
    org.opencontainers.image.description="TRL 3 proof of concept for continuous assurance of AI-enabled protective security systems" \
    org.opencontainers.image.authors="Shafiq Ahmed <csshafiqahmed@gmail.com>" \
    org.opencontainers.image.url="https://github.com/csshafiqahmed/VERITAS-AI-Continuous-Assurance-for-AI-Enabled-Protective-Security-Systems" \
    org.opencontainers.image.source="https://github.com/csshafiqahmed/VERITAS-AI-Continuous-Assurance-for-AI-Enabled-Protective-Security-Systems" \
    org.opencontainers.image.licenses="Apache-2.0" \
    org.opencontainers.image.version="${VERSION}" \
    org.opencontainers.image.revision="${VCS_REF}" \
    org.opencontainers.image.created="${BUILD_DATE}"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_NO_CACHE=1 \
    HOME=/tmp \
    PATH="/app/.venv/bin:${PATH}"

RUN apt-get update \
    && apt-get install --no-install-recommends -y libgomp1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN python -m pip install --no-cache-dir --disable-pip-version-check uv==0.8.13
COPY pyproject.toml uv.lock README.md LICENSE NOTICE ./
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

EXPOSE 8501

USER 65532:65532
ENTRYPOINT ["/app/.venv/bin/veritas-ai"]
CMD ["--help"]
