# Docker Examples

These files are examples for packaging Aegrail. They are intentionally generic:
do not put real customer paths, domains, database DSNs, node secrets, Hub
secrets, or queue/state data in Git.

The root `.dockerignore` excludes `.aegrail/`, `data/`, local env files,
dashboard dependencies/build output, and other runtime files from Docker build
contexts.

## Hub

The Hub example builds:

- the React dashboard into `/app/dashboard`
- the standalone Hub binary into `/usr/local/bin/aegrail-hub`
- migrations into `/app/migrations`
- Debian CA certificates into the runtime image so HTTPS notification providers
  such as FCM validate correctly

Prepare local env:

```powershell
Copy-Item docker\examples\.env.hub.example docker\examples\.env.hub
```

Generate a Hub wire key:

```powershell
docker compose --env-file docker/examples/.env.hub -f docker/examples/hub.compose.yaml build hub
docker compose --env-file docker/examples/.env.hub -f docker/examples/hub.compose.yaml run --rm --no-deps hub wire keygen
```

Copy the generated private key into `.env.hub`, set a strong
`AEGRAIL_HUB_USER_SECRET`, and replace the database password placeholder.
Set `AEGRAIL_HUB_PUBLIC_URL` to the URL operators will use in a browser; email
and push notifications use it for issue links.

Optional browser push keys can be generated with:

```powershell
docker compose --env-file docker/examples/.env.hub -f docker/examples/hub.compose.yaml run --rm --no-deps hub notifications vapid-keys
```

Browser push delivery is best-effort. If FCM/APNs/web-push delivery fails, Hub
keeps saved findings and correlation workers continue; fix the notification
provider or CA bundle separately.

Optional Mailjet email notifications use
`AEGRAIL_NOTIFICATION_EMAIL_USERNAME` for the Mailjet API key and
`AEGRAIL_NOTIFICATION_EMAIL_PASSWORD` for the Mailjet secret key.

Run migrations and start Hub:

```powershell
docker compose --env-file docker/examples/.env.hub -f docker/examples/hub.compose.yaml run --rm hub-migrate
docker compose --env-file docker/examples/.env.hub -f docker/examples/hub.compose.yaml up -d hub
```

Hub listens on `http://127.0.0.1:8787` by default. Put HTTPS or a private
reverse proxy in front of it before accepting non-local Agent traffic.

## Agent

Create a node in Hub first. Hub returns `node_id`, `node_secret`,
`hub_public_key`, and a sample config. Copy those values into the Agent env and
YAML files.

Prepare local env/config:

```powershell
Copy-Item docker\examples\.env.agent.example docker\examples\.env.agent
Copy-Item docker\examples\agent.yaml.example docker\examples\agent.yaml
```

Edit:

- `.env.agent`: node secret, PII key, read-only database DSNs, mounted host paths
- `agent.yaml`: Hub URL, Hub public key, identity slugs, site root, logs, URLs

Run the initial baseline:

```powershell
docker compose --env-file docker/examples/.env.agent -f docker/examples/agent.compose.yaml run --rm agent run --config /etc/aegrail/agent.yaml --once --bootstrap --discard-pending
```

Start continuous monitoring:

```powershell
docker compose --env-file docker/examples/.env.agent -f docker/examples/agent.compose.yaml up -d agent
```

The Agent container should mount site files and logs read-only. Queue and state
live in the `agent-state` Docker volume and should be treated as sensitive
runtime data.
