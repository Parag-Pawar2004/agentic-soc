# Multi-stage build producing a small standalone Next.js server.
FROM node:20-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi

FROM node:20-alpine AS build
WORKDIR /app
# "same-origin" when an ingress serves /api and /ws on the same host (Kubernetes);
# http://localhost:8000 for Docker Compose on your laptop.
ARG NEXT_PUBLIC_API_URL=same-origin
ARG NEXT_PUBLIC_DEMO_MODE=0
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL \
    NEXT_PUBLIC_DEMO_MODE=$NEXT_PUBLIC_DEMO_MODE \
    NEXT_TELEMETRY_DISABLED=1
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM node:20-alpine AS run
WORKDIR /app
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 PORT=3000 HOSTNAME=0.0.0.0
RUN addgroup -S soc && adduser -S soc -G soc
COPY --from=build /app/.next/standalone ./
COPY --from=build /app/.next/static ./.next/static
COPY --from=build /app/public ./public
USER soc
EXPOSE 3000
CMD ["node", "server.js"]
