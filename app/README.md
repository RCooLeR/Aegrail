# Aegrail App

This directory will contain the Go application.

Planned layout:

```text
app/
  go.mod
  cmd/
    aegrail/
      main.go
  internal/
    bootstrap/
    domain/
    app/
    ports/
    adapters/
      cli/
      http/
      postgres/
      filesystem/
      ollama/
    modules/
      prestashop/
    rules/
    redaction/
    reports/
  migrations/
  configs/
  testdata/
```

The binary is named `aegrail` from the start.

Useful commands:

```powershell
go run ./cmd/aegrail --help
go run ./cmd/aegrail version
go run ./cmd/aegrail init --data-dir ../data
go run ./cmd/aegrail db migrate
go run ./cmd/aegrail site add --name "Petlink Demo" --url https://petlink.example petlink
go run ./cmd/aegrail site list
$env:AEGRAIL_DATA_DIR="../data"
go run ./cmd/aegrail import files --site petlink --path testdata/evidence-sample/access.log
go run ./cmd/aegrail import logs --site petlink --path testdata/evidence-sample
go fmt ./...
go test ./...
```

Rules for this directory:

- Keep business logic out of CLI and HTTP handlers.
- Keep adapters replaceable through interfaces in `internal/ports`.
- Keep source-specific logic under `internal/modules`.
- Keep deterministic tests independent from Ollama.
