# syntax=docker/dockerfile:1.28.0@sha256:bb22d9815c728170f72750f4e5b0d672e06176142e1d602c7e66c050100b7e5b
# check=error=true

ARG NPM_VERSION=12.2.1

FROM --platform=$BUILDPLATFORM node:26.12.1-trixie-slim@sha256:36793bcbb160a6a16cede1e62b93f84e26b78a972a8a4c0b879c1c12f22761ec AS dashboard-build
ARG NPM_VERSION
WORKDIR /src/dashboard
RUN --mount=type=cache,id=aegrail-npm,target=/root/.npm,sharing=locked \
    npm install --global "npm@${NPM_VERSION}"
COPY --link dashboard/package.json dashboard/package-lock.json ./
RUN --mount=type=cache,id=aegrail-npm,target=/root/.npm,sharing=locked \
    npm ci --no-audit --no-fund
COPY --link dashboard/ ./
RUN npm run build

FROM --platform=$BUILDPLATFORM golang:1.27.3-trixie@sha256:fbb7ae40b62ff8afe31662df570d39b4f5052ac32b90dae8e60d7657a20a74f4 AS hub-build
ARG TARGETOS
ARG TARGETARCH
ENV GOTOOLCHAIN=local
WORKDIR /src/hub
COPY --link hub/go.mod hub/go.sum ./
RUN --mount=type=cache,id=aegrail-go-mod,target=/go/pkg/mod,sharing=locked \
    go mod download
COPY --link hub/ ./
RUN --mount=type=cache,id=aegrail-go-mod,target=/go/pkg/mod,sharing=locked \
    --mount=type=cache,id=aegrail-hub-build,target=/root/.cache/go-build,sharing=locked \
    CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
    go build -buildvcs=false -trimpath -ldflags="-s -w" -o /out/aegrail-hub ./cmd/hub

FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99
WORKDIR /app
COPY --link --from=hub-build /out/aegrail-hub /usr/local/bin/aegrail-hub
COPY --link --from=hub-build /src/hub/migrations /app/migrations
COPY --link --from=dashboard-build /src/dashboard/dist /app/dashboard

ENV AEGRAIL_HTTP_ADDR=0.0.0.0:8787
ENV AEGRAIL_DATA_DIR=/var/lib/aegrail/hub
ENV AEGRAIL_MIGRATIONS_DIR=/app/migrations
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

EXPOSE 8787
USER nonroot:nonroot
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["/usr/local/bin/aegrail-hub", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/aegrail-hub"]
CMD ["serve", "--dashboard-dir", "/app/dashboard"]
