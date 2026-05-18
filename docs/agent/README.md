# Agent

The Agent runs near a monitored site or hosting account. It reads a YAML config, collects local evidence, stores retry queue/state files on disk, and sends encrypted wire batches to the Hub. Successfully sent queue JSON is deleted by default.

## Under The Hood

| Area | What the Agent collects | What it sends |
| --- | --- | --- |
| Files | Profile paths, configured extra paths, file metadata, mtime, size, and SHA-256 when hashed. | File created/modified/deleted events with relative paths and hashes. No file contents. |
| Database | Read-only platform snapshots for WordPress, PrestaShop, Mautic, Yii2 RBAC, and Laravel. | Counts, entity signatures, safe account identifiers, masked hints, optional HMAC identifiers, and hashes of selected values. No DSNs, password hashes, raw tokens, or raw secrets. |
| Logs | New access/PHP/generic log lines since the saved offset. Admin login, password-reset, privileged/admin, server-error, and platform-specific security paths are kept while routine campaign/static noise can be dropped. | Normalized request/error events with query strings, cookies, auth headers, passwords, sessions, and tokens redacted. |
| Browser | Static or rendered pages from configured URLs only. | Redacted page/script URLs, script domains/paths, inline script hashes, tag-manager IDs, favicons, status/warnings, and the crawler User-Agent. |
| Coverage | Enabled collectors and safe config posture. | Collector state, disabled/optional coverage, DSN-env presence, and sanitized ignore paths. No local roots or env values. |

All normal traffic to Hub uses `aegrail.agent.wire.v1`: the queued JSON batch is encrypted with X25519-derived AES-256-GCM using the node secret and Hub public key before it leaves the node. The Hub stores the node public key/fingerprint, decrypts with its wire private key, stores events in PostgreSQL, then runs deterministic rules.

## Docs

- [Install](install.md): local setup, config validation, bootstrap, and continuous runs.
- [How It Works](how-it-works.md): collectors, schedules, SQL queries, hashes, queue format, encryption, and Hub ingest.
- [Tracker](tracker.md): Agent status, next work, and later work.

## Code

```text
agent/cmd/agent/             Agent app entrypoint.
agent/configs/               Example YAML configs.
agent/internal/agent/        Runtime, config, queue, file watch, log watch.
agent/internal/collector/    Database and browser collectors.
agent/internal/modules/      WordPress, PrestaShop, Mautic, Yii2 RBAC, and Laravel source logic.
agent/internal/redaction/    Secret and token redaction.
```

## Main Commands

```powershell
cd agent
go run ./cmd/agent --help
go run ./cmd/agent config validate --config configs/agent.multi-site.example.yaml
go run ./cmd/agent run --config configs/agent.multi-site.example.yaml --once --bootstrap
go run ./cmd/agent run --config configs/agent.multi-site.example.yaml
```

Use `--bootstrap` when introducing a site for the first time and you want the current state to become the baseline without creating first-scan noise.
