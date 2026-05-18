# syntax=docker/dockerfile:1.7

ARG GO_IMAGE=golang:1.26.2-bookworm
ARG NODE_IMAGE=node:24-bookworm-slim
ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian12:nonroot

FROM ${NODE_IMAGE} AS dashboard-build
WORKDIR /src/dashboard
COPY dashboard/package.json dashboard/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY dashboard/ ./
RUN npm run build

FROM ${GO_IMAGE} AS hub-build
WORKDIR /src/hub
COPY hub/go.mod hub/go.sum ./
RUN go mod download
COPY hub/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/aegrail-hub ./cmd/hub

FROM ${RUNTIME_IMAGE}
WORKDIR /app
COPY --from=hub-build /out/aegrail-hub /usr/local/bin/aegrail-hub
COPY --from=hub-build /src/hub/migrations /app/migrations
COPY --from=dashboard-build /src/dashboard/dist /app/dashboard

ENV AEGRAIL_HTTP_ADDR=0.0.0.0:8787
ENV AEGRAIL_DATA_DIR=/var/lib/aegrail/hub
ENV AEGRAIL_MIGRATIONS_DIR=/app/migrations

EXPOSE 8787
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/aegrail-hub"]
CMD ["serve", "--dashboard-dir", "/app/dashboard"]
