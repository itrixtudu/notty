ARG NODE_IMAGE=node:24.18.0-bookworm-slim@sha256:cb4e8f7c443347358b7875e717c29e27bf9befc8f5a26cf18af3c3dec80e58c5

FROM ${NODE_IMAGE} AS build

ENV NEXT_TELEMETRY_DISABLED=1 \
    NPM_CONFIG_FUND=false \
    NPM_CONFIG_UPDATE_NOTIFIER=false

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --include=dev --ignore-scripts

COPY components ./components
COPY modules ./modules
COPY pages ./pages
COPY styles ./styles
COPY tests ./tests
COPY next.config.js ./next.config.js

RUN npm run test:run \
    && npm run build \
    && npm prune --omit=dev --ignore-scripts

FROM ${NODE_IMAGE} AS runtime

LABEL io.notty.policy-review.ui-abi="1"

ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    NPM_CONFIG_FUND=false \
    NPM_CONFIG_UPDATE_NOTIFIER=false \
    HOSTNAME=0.0.0.0 \
    PORT=3000

WORKDIR /app

COPY --from=build --chown=node:node /app/package.json /app/package-lock.json ./
COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/.next ./.next
COPY --from=build --chown=node:node /app/next.config.js ./next.config.js

USER node
EXPOSE 3000

HEALTHCHECK --interval=1s --timeout=2s --start-period=5s --retries=30 \
  CMD ["node", "-e", "const http=require('node:http');const request=http.get('http://127.0.0.1:3000/policy-review',response=>{response.resume();process.exit(response.statusCode===200?0:1)});request.setTimeout(1500,()=>request.destroy());request.on('error',()=>process.exit(1))"]

CMD ["npm", "run", "start"]
