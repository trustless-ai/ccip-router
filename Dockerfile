FROM node:20-alpine AS base
WORKDIR /app

# Install build tools for better-sqlite3 native module
RUN apk add --no-cache python3 make g++

# Dependencies
FROM base AS deps
COPY package*.json ./
RUN npm ci --ignore-scripts=false

# Build
FROM deps AS builder
COPY . .
RUN npm run build

# Runtime — lean image
FROM node:20-alpine AS runner
WORKDIR /app

RUN apk add --no-cache python3 make g++

COPY package*.json ./
RUN npm ci --omit=dev --ignore-scripts=false

COPY --from=builder /app/dist ./dist
COPY --from=builder /app/public ./public

RUN mkdir -p /data

ENV PORT=3000
ENV DB_PATH=/data/data.db
ENV SYNC_NAMESPACE=agent-attestations
ENV SYNC_INTERVAL="*/5 * * * *"

EXPOSE 3000

CMD ["node", "dist/index.js"]
