# syntax=docker/dockerfile:1
# Web image: Next.js standalone output. Build context = repo root.
#
# The optional `build_extra_ca` secret adds a root CA for downloads only (TLS-inspecting
# antivirus or proxies; see infrastructure/certs/README.md). It never ends up in the image.

# node 26-bookworm-slim (26.13.1)
FROM node@sha256:5df79989ed685e09f0a98019db4cebfb22fb9df1a53c0161664a011f7ff6b0f1 AS build
ENV NEXT_TELEMETRY_DISABLED=1
RUN --mount=type=secret,id=build_extra_ca,required=false \
    if [ -s /run/secrets/build_extra_ca ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/build_extra_ca; fi; \
    npm install -g pnpm@12.21.0 --silent
WORKDIR /src
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY frontend/package.json frontend/
RUN --mount=type=cache,target=/root/.local/share/pnpm/store \
    --mount=type=secret,id=build_extra_ca,required=false \
    if [ -s /run/secrets/build_extra_ca ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/build_extra_ca; fi; \
    pnpm install --frozen-lockfile --filter frontend
COPY frontend frontend
RUN pnpm --filter frontend build

FROM node@sha256:5df79989ed685e09f0a98019db4cebfb22fb9df1a53c0161664a011f7ff6b0f1 AS runtime
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 HOSTNAME=0.0.0.0 PORT=3000
WORKDIR /app
COPY --from=build --chown=root:root /src/frontend/.next/standalone ./
COPY --from=build --chown=root:root /src/frontend/.next/static ./frontend/.next/static
COPY --from=build --chown=root:root /src/frontend/public ./frontend/public
USER node
EXPOSE 3000
CMD ["node", "frontend/server.js"]
