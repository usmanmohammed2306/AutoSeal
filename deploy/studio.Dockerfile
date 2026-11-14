FROM node:24-bookworm-slim@sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54 AS build
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
RUN npm install --global pnpm@12.6.0
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY app ./app
COPY lib ./lib
COPY next.config.ts next-env.d.ts tsconfig.json proxy.ts ./
RUN pnpm build

FROM node:24-bookworm-slim@sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1
WORKDIR /app
COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/.next ./.next
COPY --from=build --chown=node:node /app/package.json /app/next.config.ts ./
COPY --from=build --chown=node:node /app/app ./reference-source/app
COPY --from=build --chown=node:node /app/lib ./reference-source/lib
COPY --from=build --chown=node:node /app/package.json /app/pnpm-lock.yaml /app/proxy.ts /app/next.config.ts /app/tsconfig.json ./reference-source/
USER node
EXPOSE 3000
CMD ["node", "node_modules/next/dist/bin/next", "start", "--hostname", "0.0.0.0", "--port", "3000"]
