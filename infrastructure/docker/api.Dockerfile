# syntax=docker/dockerfile:1
# API image: FastAPI app from the uv workspace. Build context = repo root.
#
# The optional `build_extra_ca` secret adds a root CA for downloads only (TLS-inspecting
# antivirus or proxies; see infrastructure/certs/README.md). It never ends up in the image.

# uv 0.13.8
FROM ghcr.io/astral-sh/uv@sha256:5cc1805e2426484abca4ad46ea783bab281fdb225fd82d8ce6d66a81254bac85 AS uv

# python 3.12-slim
FROM python@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS build
COPY --from=uv /uv /bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
WORKDIR /src

# Dependency layer: lock file plus every workspace member manifest.
COPY pyproject.toml uv.lock ./
COPY backend/pyproject.toml backend/
COPY connectors/sdk/pyproject.toml connectors/sdk/
COPY connectors/runner/pyproject.toml connectors/runner/
COPY ai-engine/gateway/pyproject.toml ai-engine/gateway/
COPY automation/worker/pyproject.toml automation/worker/
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=secret,id=build_extra_ca,required=false \
    if [ -s /run/secrets/build_extra_ca ]; then \
      cat /etc/ssl/certs/ca-certificates.crt /run/secrets/build_extra_ca > /tmp/ca.pem; \
      export SSL_CERT_FILE=/tmp/ca.pem; \
    fi; \
    uv sync --frozen --no-dev --package nocsoc-api --no-install-workspace; \
    rm -f /tmp/ca.pem

FROM python@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS runtime
RUN groupadd --system --gid 10001 app && useradd --system --uid 10001 --gid app --no-create-home app
COPY --from=build --chown=root:root /src/.venv /src/.venv
# The application runs from source (no wheel build needed); files are root-owned and read-only.
COPY --chown=root:root backend/app /src/backend/app
ENV PATH="/src/.venv/bin:$PATH" PYTHONPATH=/src/backend PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /src/backend
USER 10001
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
