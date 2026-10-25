# syntax=docker/dockerfile:1.28.0@sha256:bb22d9815c728170f72750f4e5b0d672e06176142e1d602c7e66c050100b7e5b
# check=error=true

FROM --platform=$BUILDPLATFORM golang:1.27.3-trixie@sha256:fbb7ae40b62ff8afe31662df570d39b4f5052ac32b90dae8e60d7657a20a74f4 AS agent-build
ARG TARGETOS
ARG TARGETARCH
ENV GOTOOLCHAIN=local
WORKDIR /src/agent
COPY --link agent/go.mod agent/go.sum ./
RUN --mount=type=cache,id=aegrail-go-mod,target=/go/pkg/mod,sharing=locked \
    go mod download
COPY --link agent/ ./
RUN --mount=type=cache,id=aegrail-go-mod,target=/go/pkg/mod,sharing=locked \
    --mount=type=cache,id=aegrail-agent-build,target=/root/.cache/go-build,sharing=locked \
    CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
    go build -buildvcs=false -trimpath -ldflags="-s -w" -o /out/aegrail-agent ./cmd/agent

FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99
WORKDIR /app
COPY --link --from=agent-build /out/aegrail-agent /usr/local/bin/aegrail-agent

ENV AEGRAIL_CONFIG=/etc/aegrail/agent.yaml
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/aegrail-agent"]
CMD ["run", "--config", "/etc/aegrail/agent.yaml"]
