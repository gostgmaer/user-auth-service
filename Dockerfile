# ─── Stage 1: Install dependencies ───────────────────────────────────────────
FROM node:20-alpine AS deps
WORKDIR /app

# Install only production deps in this stage
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

# ─── Stage 2: Production image ────────────────────────────────────────────────
FROM node:20-alpine AS production
WORKDIR /app

# dumb-init is a minimal process supervisor that:
#  1. Properly reaps zombie processes (important in containers)
#  2. Forwards SIGTERM/SIGINT to the Node.js process (enables graceful shutdown)
RUN apk add --no-cache dumb-init

# Non-root user for security
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Copy dependencies from deps stage
COPY --from=deps /app/node_modules ./node_modules

# Copy application source
COPY --chown=appuser:appgroup . .

# Pre-create the log directory so the app can write without root
RUN mkdir -p logs && chown appuser:appgroup logs

# Remove dev artifacts not needed in production
RUN rm -rf .git coverage tests __tests__ *.test.js *.spec.js

USER appuser

# Soft RSS cap: keep the heap under 460 MiB (container limit recommended: 512 MiB).
# --expose-gc is optional but enables manual GC if a heap-diagnostic tool is attached.
ENV NODE_OPTIONS="--max-old-space-size=460"
ENV NODE_ENV=production

EXPOSE 4002

# Use dumb-init as PID 1 — properly forwards OS signals to Node.js
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:4002/health/live || exit 1

ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["node", "server.js"]
