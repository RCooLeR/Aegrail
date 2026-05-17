# Hub Agent API

The Agent API is the ingest surface used by Agents. Agents must use `aegrail.agent.wire.v1`, which encrypts the JSON payload before it leaves the node.

## Wire V1

Hub creates a node and returns a one-time sample config containing:

```text
node_id
node_secret
hub_public_key
```

`node_secret` is the node X25519 private key. Hub stores only the node public key and fingerprint. Hub decrypts with `AEGRAIL_HUB_WIRE_PRIVATE_KEY`.

Agent request body:

```json
{
  "schema": "aegrail.agent.wire.v1",
  "node_id": "node-web-01",
  "timestamp": "2026-05-17T00:00:00Z",
  "nonce": "base64url",
  "ciphertext": "base64url"
}
```

Encryption:

- key agreement: X25519 node private key to Hub public key
- key derivation: HMAC-SHA256 based KDF scoped to `aegrail-wire-v1:<node_id>`
- payload cipher: AES-256-GCM
- associated data: schema, node ID, and timestamp
- timestamp skew: controlled by Hub wire timestamp skew

The encrypted plaintext is the normal ingest JSON batch.

## Ingest Events

```text
POST /api/v1/ingest/events
```

Request body:

```json
{
  "org": "acme",
  "project": "customer-site",
  "environment": "production",
  "app": "main-web",
  "service": "frontend",
  "host": "web-01",
  "agent_id": "agt_web_01",
  "batch_id": "batch-unique-id",
  "source": "agent",
  "region": "eu-central",
  "labels": {
    "provider": "vps"
  },
  "events": [
    {
      "time": "2026-05-17T00:00:00Z",
      "type": "file.modified",
      "target": "wp-content/plugins/example/example.php",
      "severity": "warning",
      "message": "file modified",
      "region": "eu-central",
      "labels": {
        "collector": "files"
      },
      "payload": {
        "relative_path": "wp-content/plugins/example/example.php",
        "sha256": "one-way-file-content-hash"
      }
    }
  ]
}
```

Response body is JSON and includes accepted batch/event counts. Existing external batch IDs are handled idempotently.

## Event Rules

- `time` should be when the event happened, not when it was discovered, when the source provides a trustworthy timestamp.
- File events include metadata and hashes, not file contents.
- Database events include counts, selected safe fields, one-way hashes, and account identity where needed for operator action.
- Log and browser URL fields must be redacted before sending.
- Browser crawl events include the crawler `user_agent`; default Agents identify as `AegrailBot/0.1 (+https://aegrail.local/monitoring; Aegrail bot)`.
- Browser script payloads should use redacted `url`/`url_redacted` values plus separate `domain`, `path`, `sha256`, and tag-manager fields for drift detection.
- Local filesystem roots, DSNs, secrets, cookies, and tokens must not be sent.

## Provisioning APIs

Dashboard Settings uses these Hub routes:

| Method | Route | Access | Purpose |
| --- | --- | --- | --- |
| `POST` | `/api/v1/inventory/companies` | admin | Create/update a company. |
| `POST` | `/api/v1/inventory/sites` | admin | Create/update a site project, environment, app, and service. |
| `POST` | `/api/v1/inventory/nodes` | admin | Create/update a node, generate node keys, store the node public key, and return a sample Agent config. |

`POST /api/v1/inventory/nodes` requires `AEGRAIL_HUB_WIRE_PRIVATE_KEY` so Hub can derive and show the matching Hub public key.
