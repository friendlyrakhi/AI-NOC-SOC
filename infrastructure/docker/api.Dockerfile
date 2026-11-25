# syntax=docker/dockerfile:1
# API image: FastAPI app from the uv workspace. Build context = repo root.
#
# The optional `build_extra_ca` secret adds a root CA for downloads only (TLS-inspecting
# antivirus or proxies; see infrastructure/certs/README.md). It never ends up in the image.

# uv 0.13.8
FROM ghcr.io/astral-sh/uv@sha256:a3ea1357342c1a4bf9a0c53a3deb1b55379aefa037338d8113d5771efa01774f AS uv

# python 3.12-slim
FROM python@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS build
COPY --from=uv /uv /bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
WORKDIR /src

# Dependency layer: lock file plus every workspace member manifest.
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
    uv sync --frozen --no-dev --package nocsoc-api --no-install-workspace; \
    rm -f /tmp/ca.pem

FROM python@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS runtime
RUN groupadd --system --gid 10001 app && useradd --system --uid 10001 --gid app --no-create-home app
COPY --from=build --chown=root:root /src/.venv /src/.venv
# The application runs from source (no wheel build needed); files are root-owned and read-only.
COPY --chown=root:root backend/app /src/backend/app
COPY --chown=root:root backend/migrations /src/backend/migrations
COPY --chown=root:root backend/alembic.ini /src/backend/alembic.ini
# Workspace libraries used by ingestion (normalizers) and sandbox scenarios. The image also
# serves as the ingest worker and stream-migration one-shots (different command).
COPY --chown=root:root connectors/sdk/src /src/connectors/sdk/src
COPY --chown=root:root connectors/catalog/src /src/connectors/catalog/src
ENV PATH="/src/.venv/bin:$PATH" \
    PYTHONPATH=/src/backend:/src/connectors/sdk/src:/src/connectors/catalog/src \
    PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /src/backend
# Mount points for named volumes (P7): audit anchors, and the hardened profile's OpenBao init and
# AppRole volumes. A fresh named volume inherits the ownership of its mount point.
RUN mkdir -p /var/lib/nocsoc/anchors /var/lib/openbao-init /run/openbao     && chown 10001:10001 /var/lib/nocsoc/anchors /var/lib/openbao-init /run/openbao     && chmod 0700 /var/lib/openbao-init
USER 10001
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
