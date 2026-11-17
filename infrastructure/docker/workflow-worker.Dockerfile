# syntax=docker/dockerfile:1
# Workflow worker: runs Temporal workflows (playbooks, approvals) and is the only runtime that
# executes actions, in simulate or dry-run mode, through sandbox connectors. Like the connector
# runner it has no database credentials: it claims each action from the API, which re-checks
# approvals, expiry and the kill switch in the database (threat model T21).

# uv 0.13.8
FROM ghcr.io/astral-sh/uv@sha256:5cc1805e2426484abca4ad46ea783bab281fdb225fd82d8ce6d66a81254bac85 AS uv

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
    uv sync --frozen --no-dev --package nocsoc-workflow-worker --no-install-workspace; \
    rm -f /tmp/ca.pem

FROM python@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS runtime
RUN groupadd --system --gid 10001 app && useradd --system --uid 10001 --gid app --no-create-home app
COPY --from=build --chown=root:root /src/.venv /src/.venv
COPY --chown=root:root connectors/sdk/src /src/connectors/sdk/src
COPY --chown=root:root connectors/catalog/src /src/connectors/catalog/src
COPY --chown=root:root automation/worker/src /src/automation/worker/src
ENV PATH="/src/.venv/bin:$PATH" \
    PYTHONPATH=/src/connectors/sdk/src:/src/connectors/catalog/src:/src/automation/worker/src \
    PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /src
USER 10001
CMD ["python", "-m", "workflow_worker"]
