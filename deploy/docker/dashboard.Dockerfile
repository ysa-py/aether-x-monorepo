# Multi-stage build for the Next.js NOC dashboard.
#
# Build context: the MONOREPO ROOT.
#   docker build -f deploy/docker/dashboard.Dockerfile .
#
# Relies on `output: "standalone"` in aether-x-dashboard/next.config.mjs, which
# emits a self-contained server bundle carrying only the traced runtime deps.
#
# NOTE ON NEXT_PUBLIC_* : variables prefixed `NEXT_PUBLIC_` are inlined into the
# client bundle at BUILD time, not read at runtime. `NEXT_PUBLIC_API_BASE` is
# therefore a build arg here. Setting it only as a runtime environment variable
# has no effect on the browser bundle — a common and confusing deployment trap.
# It must also be an address the USER'S BROWSER can resolve (a public control
# plane URL), not an internal service name, because the request is made by the
# browser rather than by the container.

FROM node:20-bookworm-slim AS deps
WORKDIR /app
# Dependency layer first so ordinary source edits keep this cached.
COPY aether-x-dashboard/package.json aether-x-dashboard/package-lock.json ./
RUN npm ci --no-audit --no-fund

FROM node:20-bookworm-slim AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY aether-x-dashboard/ ./
# Public base URL of the control plane, baked into the client bundle.
ARG NEXT_PUBLIC_API_BASE="http://localhost:8080"
ENV NEXT_PUBLIC_API_BASE=${NEXT_PUBLIC_API_BASE}
ENV NEXT_TELEMETRY_DISABLED=1
RUN npx next build

FROM node:20-bookworm-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
# Bind all interfaces so the platform's health check can reach the container.
ENV HOSTNAME=0.0.0.0
ENV PORT=3000

RUN groupadd --system --gid 10003 nodejs \
    && useradd --system --uid 10003 --gid nodejs nextjs

# The standalone bundle, plus the two directories it expects beside it.
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static
COPY --from=builder --chown=nextjs:nodejs /app/public ./public

USER nextjs
EXPOSE 3000
CMD ["node", "server.js"]
