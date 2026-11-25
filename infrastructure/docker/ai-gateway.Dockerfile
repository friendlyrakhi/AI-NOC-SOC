# syntax=docker/dockerfile:1
# AI gateway: model provider adapters, redaction, prompt templates, structured output.
# Separate image and process (docs/02 §6.6). It contains no platform, connector or runner code
# (import-linter), holds the only model credentials, and in compose it sits on an internal-only
# network with the API alone: no data stores, no event bus, no runner, no internet by default.

# uv 0.13.8
FROM ghcr.io/astral-sh/uv@sha256:a3ea1357342c1a4bf9a0c53a3deb1b55379aefa037338d8113d5771efa01774f AS uv

# python 3.12-slim
FROM python@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS build
COPY --from=uv /uv /bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
WORKDIR /src

COPY pyproject.toml uv.lock ./
COPY backend/pyproject.toml backend/
COPY connectors/sdk/pyproject.toml connectors/sdk/
COPY connectors/catalog/pyproject.toml connectors/catalog/
COPY connectors/runner/pyproject.toml connectors/runner/
COPY ai-engine/gateway/pyproject.toml ai-engine/gateway/
COPY automation/worker/pyproject.toml automation/worker/
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=secret,id=build_extra_ca,required=false \
    if [ -s /run/secrets/build_extra_ca ]; then \
      cat /etc/ssl/certs/ca-certificates.crt /run/secrets/build_extra_ca > /tmp/ca.pem; \
      export SSL_CERT_FILE=/tmp/ca.pem; \
    fi; \
    uv sync --frozen --no-dev --package nocsoc-ai-gateway --no-install-workspace; \
    rm -f /tmp/ca.pem

FROM python@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS runtime
RUN groupadd --system --gid 10001 app && useradd --system --uid 10001 --gid app --no-create-home app
COPY --from=build --chown=root:root /src/.venv /src/.venv
COPY --chown=root:root ai-engine/gateway/src /src/ai-engine/gateway/src
COPY --chown=root:root ai-engine/prompts /src/ai-engine/prompts
ENV PATH="/src/.venv/bin:$PATH" \
    PYTHONPATH=/src/ai-engine/gateway/src \
    NOCSOC_AI_PROMPTS_DIR=/src/ai-engine/prompts \
    PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /src
USER 10001
EXPOSE 8200
CMD ["python", "-m", "ai_gateway"]
