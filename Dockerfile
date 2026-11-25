# syntax=docker/dockerfile:1

# Node.js 24 is an Active LTS line. The base image is pinned by DIGEST so builds are reproducible and a
# moved tag cannot silently change what we ship. To update: `docker pull node:24-alpine`, then copy the
# digest from `docker image inspect node:24-alpine --format '{{index .RepoDigests 0}}'`.
ARG NODE_IMAGE=node:24-alpine@sha256:116b800c3754b440ee0aa3ed2f20f5bf3d99a554bfd9adeea09ea8017f6e85f5

# ---- deps: all dependencies (build + test tooling) ----
FROM ${NODE_IMAGE} AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

# ---- build: compile TypeScript ----
FROM deps AS build
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN npm run build

# ---- test (optional): docker build --target test . ----
FROM build AS test
COPY tests ./tests
COPY .gitignore .dockerignore .env.example compose.yaml Dockerfile ./
RUN npm test

# ---- prod-deps: runtime dependencies only ----
FROM ${NODE_IMAGE} AS prod-deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

# ---- runtime ----
FROM ${NODE_IMAGE} AS runtime
ENV NODE_ENV=production \
    PORT=3000 \
    AUDIT_FILE_PATH=/app/data/audit.jsonl
WORKDIR /app

COPY --from=prod-deps --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/dist ./dist
COPY --chown=node:node package.json ./

# Data directory owned by the unprivileged user, so a named volume mounted here inherits it.
RUN mkdir -p /app/data && chown node:node /app/data
USER node

EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

# No secrets are baked into the image: the key is supplied at runtime (AUDIT_ENCRYPTION_KEY_FILE).
CMD ["node", "dist/server.js"]
