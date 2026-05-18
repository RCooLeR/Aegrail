# syntax=docker/dockerfile:1.7

ARG GO_IMAGE=golang:1.26.2-bookworm
ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian12:nonroot

FROM ${GO_IMAGE} AS agent-build
WORKDIR /src/agent
COPY agent/go.mod agent/go.sum ./
RUN go mod download
COPY agent/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/aegrail-agent ./cmd/agent

FROM ${RUNTIME_IMAGE}
WORKDIR /app
COPY --from=agent-build /out/aegrail-agent /usr/local/bin/aegrail-agent

ENV AEGRAIL_CONFIG=/etc/aegrail/agent.yaml

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/aegrail-agent"]
CMD ["run", "--config", "/etc/aegrail/agent.yaml"]
