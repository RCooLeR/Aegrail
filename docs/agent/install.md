# Agent Install

## Prerequisites

- Go matching the version in `agent/go.mod`.
- Read access to the site files you want to monitor.
- Read-only database credentials for database snapshots.
- Network access from the Agent to the Hub ingest URL.

## Configure

Start from the full commented example:

```powershell
cd agent
Copy-Item configs\agent.full.example.yaml .aegrail\agent.yaml
```

Do not commit local config files. Keep real roots, domains, DSNs, and secrets outside the repository.

Required config areas:

- `hub.url`: Hub URL. Use HTTPS outside localhost/private development networks.
- `hub.protocol`: use `aegrail-wire-v1` for new nodes.
- `hub.hub_public_key`: Hub public key shown when the Hub creates the node.
- `hub.node_secret` or `hub.node_secret_env`: node private key shown once when the Hub creates the node.
- `identity`: organization, project, environment, host, agent ID, labels.
- `runtime.queue_dir` and `runtime.state_dir`: local sensitive runtime directories.
- `sites[]`: one or more monitored sites.

Database DSNs should be stored in environment variables referenced by `dsn_env`. Literal DSNs with credentials are rejected by validation.

## Environment

```powershell
$env:AEGRAIL_PII_KEY = "replace-with-agent-side-hmac-key"
```

For production, prefer `hub.node_secret_env` so the node secret lives in the host environment instead of the YAML file. The Hub still shows the value only once when the node is created.

Optional controls:

```text
AEGRAIL_CONFIG_COVERAGE_HEARTBEAT_INTERVAL
AEGRAIL_WATCH_FULL_HASH_INTERVAL
AEGRAIL_TOR_CHECK
AEGRAIL_DISABLE_TOR_CHECK
AEGRAIL_TOR_EXIT_LIST_URL
AEGRAIL_TOR_EXIT_LIST_CACHE
AEGRAIL_TOR_EXIT_LIST_TTL
```

## Validate

```powershell
cd agent
go run ./cmd/agent config validate --config .aegrail\agent.yaml
```

## First Baseline

Capture current file, database, browser, log, and coverage state without queueing first-scan findings:

```powershell
go run ./cmd/agent run --config .aegrail\agent.yaml --once --bootstrap
```

If old pending queue files exist and should not be replayed after the baseline:

```powershell
go run ./cmd/agent run --config .aegrail\agent.yaml --once --bootstrap --discard-pending
```

## Normal Runs

Run one pass:

```powershell
go run ./cmd/agent run --config .aegrail\agent.yaml --once
```

Run continuously:

```powershell
go run ./cmd/agent run --config .aegrail\agent.yaml
```

## Verification

```powershell
cd agent
go test ./...
go run ./cmd/agent --help
```
