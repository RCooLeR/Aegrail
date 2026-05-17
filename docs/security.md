# Security And Data Handling

Aegrail must be useful without leaking private project details.

## Privacy And Redaction

Data handling rules:

- Do not commit real customer paths, domains, database DSNs, passwords, tokens, cookies, local queue/state files, or environment dumps.
- Agent coverage payloads do not include local filesystem roots.
- Database DSNs must come from environment variables such as `dsn_env`; literal DSNs with passwords are rejected.
- File evidence does not include file contents.
- Browser/log URLs are redacted for token, session, password, secret, and API-key-like query values before they leave the Agent queue.
- Browser script attributes such as `src` are redacted before sending. The Hub should receive script domain/path/hash evidence, not private query material.
- Free-text log/error evidence is pattern-redacted for credentials, cookies, and authorization-like assignments.
- Database user/employee evidence may include full normalized emails/logins because the operator needs to know which account changed.
- Set `AEGRAIL_PII_KEY` on agents that collect database users or employees to add stable one-way HMAC fingerprints for account identifiers.
- Evidence sent to LLMs must be compact, redacted, and hashable.
- Dashboard-triggered LLM analysis is generated from persisted Hub findings, not raw site files. The Hub builds an evidence bundle, applies redaction and truncation, places untrusted issue/evidence text inside explicit prompt delimiters, hashes the bundle and prompt, calls the configured model gateway, then saves the report and provenance in PostgreSQL.
- Automatic issue-queue analysis uses the same path. It skips a finding when the Hub already has a model report for the current evidence bundle hash, so repeated scans do not resend unchanged evidence.
- TOTP enrollment uses a pending flow. The Hub returns a QR/secret once, requires a valid current code, then promotes the encrypted pending secret to the active 2FA secret.
- Dashboard access requires an authenticated Hub session and active 2FA when the user has `two_factor_required` enabled. Password-only sessions for required-2FA users can only enroll/verify their own TOTP setup.
- Hub refuses to delete, disable, or downgrade the last active owner account. PostgreSQL repeats that guard inside the update/delete transaction so concurrent admin changes cannot leave the Hub without an owner.
- Hub user creation is insert-only by normalized email. Duplicate emails return `409` and cannot overwrite access level, status, password hash, or 2FA requirement through the create endpoint.
- TOTP codes are single-use inside the accepted verification window. Login/TOTP endpoints use Redis-backed rate limiting when Redis is configured and a process-local limiter as fallback.

## Transport And Storage

- Agent batches use `aegrail.agent.wire.v1`: the Agent encrypts the raw ingest JSON with X25519-derived AES-256-GCM using the node secret and Hub public key.
- Browser crawling identifies itself as `AegrailBot/0.1 (+https://aegrail.local/monitoring; Aegrail bot)` by default. Browser-like fallback User-Agents are used only for compatibility when the named bot is blocked or fails with bot-filter status codes.
- The Hub stores the node public key, decrypts with `AEGRAIL_HUB_WIRE_PRIVATE_KEY`, and rejects invalid ciphertext or timestamps outside the configured skew window.
- Raw JSON ingest is not accepted. Agent traffic must arrive as an encrypted wire envelope.
- Wire v1 protects the JSON payload, but transfer confidentiality still matters for HTTP metadata, cookies, and dashboard sessions. Use `https://` or a trusted private tunnel/VPN outside localhost.
- Hub only trusts `X-Forwarded-Proto` and `X-Forwarded-Host` from loopback or CIDRs explicitly listed in `AEGRAIL_TRUSTED_PROXY_CIDRS`. Public or direct LAN clients cannot make the Hub treat spoofed forwarded headers as transport truth unless the deployment deliberately trusts that source network.
- Hub only returns newly generated `node_secret` material from node provisioning over HTTPS or loopback requests. Node provisioning refuses to silently replace an existing agent wire public key; key rotation should be an explicit operator action.
- Hub user TOTP secrets are encrypted at rest with AES-GCM using an HKDF-SHA-256 v2 key derived from `AEGRAIL_HUB_USER_SECRET`. If that secret is lost, existing TOTP secrets cannot be verified and users must be re-enrolled.
- Dashboard mutating requests use `aegrail.dashboard.v1` with an HttpOnly session cookie and a CSRF token in `X-Aegrail-CSRF`. The token is derived with a Hub-side secret, not from the session token alone. Hub refuses to create a dashboard-auth router with users enabled unless the CSRF secret is configured.
- Local agent queue/state files are JSON on disk, created with restrictive file permissions where the OS supports them. State writes use temp-file, flush, and rename semantics; pending queue batches are flushed before send eligibility. Treat `queue_dir` and `state_dir` as sensitive runtime data. Successfully sent queue batches are deleted by default; set `runtime.sent_retention` only for short debugging windows.
- Hub stores accepted events, payloads, findings, reports, users, and audit-relevant metadata in PostgreSQL. Protect the database with normal database access controls, disk encryption/backup policy, and network restrictions.

## Secret Roles

- `AEGRAIL_HUB_WIRE_PRIVATE_KEY`: Hub X25519 private key for decrypting Agent wire v1 envelopes.
- `AEGRAIL_PII_KEY`: optional agent-side key for one-way HMAC fingerprints of account identifiers.
- `AEGRAIL_HUB_USER_SECRET`: Hub-side encryption secret for user security material such as pending and active TOTP secrets, and for dashboard CSRF token derivation.

## Operating Checklist

Before using Aegrail on real projects:

- Generate and protect a strong `AEGRAIL_HUB_WIRE_PRIVATE_KEY`.
- Generate and protect a strong `AEGRAIL_HUB_USER_SECRET`; Hub `serve` refuses to start without both Hub secrets.
- Set `AEGRAIL_DATABASE_URL`; Hub `serve` refuses to start without an explicit database URL.
- Use a separate strong `AEGRAIL_PII_KEY`.
- Use `https://` Hub URLs or a private tunnel/VPN for any agent outside the same local machine.
- Keep Hub behind local network/VPN/reverse proxy authentication.
- Use read-only database users where possible.
- Keep `data/`, `.aegrail/`, queue directories, state directories, and generated reports out of Git.
- Restrict filesystem permissions on agent `queue_dir` and `state_dir`.
- Treat Hub PostgreSQL storage as sensitive because event payloads can include account identifiers and operational evidence.
- Review findings before creating reports for customers.
- Do not paste local project paths or real customer environment values into docs.
- Review file ignore rules before adding broad paths. Ignoring a directory suppresses future Hub findings for matching file events; it does not delete existing evidence.
- Agent config coverage exposes only a safe subset of agent config. It must not include local roots, DSNs, passwords, tokens, or raw environment values. File ignore paths are reported relative to the site root when possible.
