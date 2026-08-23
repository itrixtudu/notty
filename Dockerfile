FROM node:24.18.0-bookworm-slim@sha256:cb4e8f7c443347358b7875e717c29e27bf9befc8f5a26cf18af3c3dec80e58c5

ENV NEXT_TELEMETRY_DISABLED=1 \
    NPM_CONFIG_AUDIT=false \
    NPM_CONFIG_FUND=false \
    NPM_CONFIG_UPDATE_NOTIFIER=false \
    NODE_ENV=production

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    g++ \
    make \
    python3 \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://antigravity.google/cli/install.sh | bash
ENV PATH="/root/.local/bin:${PATH}"

WORKDIR /app

COPY package*.json ./
RUN npm ci --ignore-scripts --legacy-peer-deps \
    && npm rebuild node-pty --unsafe-perm \
    && npm cache clean --force

COPY . .
RUN npx next build

EXPOSE 3000
CMD ["npm", "run", "start:next:sse"]
