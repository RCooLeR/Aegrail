# Hub Dashboard API

Dashboard APIs are served by the Hub under `/api/v1`. Dashboard routes require a Hub user session, active 2FA, and an access level.

## Dashboard Protocol V1

The browser dashboard speaks `aegrail.dashboard.v1`.

Session flow:

1. `POST /api/v1/auth/login` verifies email/password.
2. If TOTP is already enabled, the login request must include a valid `totp_code`.
3. Hub returns an HttpOnly `aegrail_session` cookie and a `csrf_token`.
4. If the user has not enrolled 2FA yet, Hub returns `dashboard_ready: false` and `totp_setup_required: true`. Only the self-enrollment routes are usable.
5. After TOTP verification, `GET /api/v1/auth/me` returns `dashboard_ready: true`.

Every dashboard request sends:

```text
X-Aegrail-Dashboard-Protocol: aegrail.dashboard.v1
```

Every mutating dashboard request also sends:

```text
X-Aegrail-CSRF: <csrf_token from auth/me or auth/login>
```

Hub rejects mutating requests with a missing/invalid protocol header or CSRF token. The CSRF token is bound to the HttpOnly session cookie. `/healthz` and Agent ingest are not part of the dashboard protocol.

Login and TOTP verification endpoints are rate-limited per process. TOTP codes
are consumed after a successful verification and cannot be replayed inside the
accepted verification window.

Access levels used by the router:

- `viewer`: read-only dashboard access
- `operator`: triage and allowlist actions
- `admin`: user and access management

## Public And Session Routes

| Method | Route | Access | Purpose |
| --- | --- | --- | --- |
| `GET` | `/healthz` | public | Dependency-aware health check; returns `503` when required services are unhealthy. |
| `GET` | `/api/v1/auth/me` | session-aware | Current auth/session state. |
| `POST` | `/api/v1/auth/login` | public | Login with email/password and optional TOTP code. |
| `POST` | `/api/v1/auth/logout` | session | Revoke the current session. |
| `POST` | `/api/v1/auth/totp/start` | setup session | Start current-user TOTP enrollment before dashboard access. |
| `POST` | `/api/v1/auth/totp/verify` | setup session | Verify current-user TOTP and unlock dashboard access. |

## Findings And Signals

| Method | Route | Access | Purpose |
| --- | --- | --- | --- |
| `GET` | `/api/v1/findings` | viewer | List findings by scope. |
| `GET` | `/api/v1/findings/{id}` | viewer | Get one finding with evidence. |
| `PATCH` | `/api/v1/findings/{id}/status` | operator | Set `open`, `acknowledged`, `resolved`, or `false_positive`. |
| `POST` | `/api/v1/findings/baseline` | operator | Accept current open findings as initial baseline. |
| `POST` | `/api/v1/findings/{id}/file-ignore` | operator | Create a scoped file ignore rule from a finding. |
| `POST` | `/api/v1/findings/{id}/browser-script-allowlist` | operator | Allow a browser script value from a finding. |
| `GET` | `/api/v1/timeline` | viewer | List normalized timeline events/signals. |
| `GET` | `/api/v1/coverage` | viewer | List Agent config coverage snapshots. |
| `GET` | `/api/v1/rules` | viewer | List registered detection rules. |

Common filters:

```text
org
project
environment
app
since
limit
```

## Browser Scripts And Deployments

| Method | Route | Access | Purpose |
| --- | --- | --- | --- |
| `GET` | `/api/v1/browser/scripts` | viewer | List observed browser scripts. |
| `GET` | `/api/v1/browser/script-allowlist` | viewer | List script allowlist entries. |
| `POST` | `/api/v1/browser/script-allowlist` | operator | Add a domain, inline hash, or tag-manager ID allowlist entry. |
| `PATCH` | `/api/v1/browser/script-allowlist/{id}/status` | operator | Enable/disable an allowlist entry. |
| `GET` | `/api/v1/deployments` | viewer | List deployment markers. |
| `POST` | `/api/v1/deployments` | operator | Create a deployment marker. |

## Model Analysis And Reports

| Method | Route | Access | Purpose |
| --- | --- | --- | --- |
| `POST` | `/api/v1/findings/{id}/model-analysis` | operator | Generate a model report for one finding. |
| `GET` | `/api/v1/findings/{id}/model-analysis` | viewer | List model reports for one finding. |
| `GET` | `/api/v1/model-analysis` | viewer | List model reports. |
| `GET` | `/api/v1/reports/finding-review` | viewer | Return findings with deterministic Hub guidance and latest model report side by side. |
| `GET` | `/api/v1/reports/model-analysis` | viewer | List model reports. |
| `GET` | `/api/v1/reports/model-analysis/{id}` | viewer | Get one model report. |

## Users And Inventory

| Method | Route | Access | Purpose |
| --- | --- | --- | --- |
| `GET` | `/api/v1/access/users` | admin | List Hub users. |
| `POST` | `/api/v1/access/users` | bootstrap/admin path | Create a Hub user. Duplicate normalized emails return `409` and do not update existing users. |
| `PATCH` | `/api/v1/access/users/{id}` | admin | Update user display/access/status settings. |
| `DELETE` | `/api/v1/access/users/{id}` | admin | Delete a Hub user. A user cannot delete their own account or the last active owner. |
| `POST` | `/api/v1/access/users/{id}/totp/start` | admin | Start pending TOTP enrollment and return QR/secret once. |
| `POST` | `/api/v1/access/users/{id}/totp/verify` | admin | Verify current code and activate TOTP. |
| `DELETE` | `/api/v1/access/users/{id}/totp` | admin | Disable TOTP. |
| `GET` | `/api/v1/inventory/scopes` | viewer | List the full organization/project/environment/app/service/host/agent tree. |
| `GET` | `/api/v1/inventory/apps` | viewer | List apps for a scope. |
| `GET` | `/api/v1/inventory/services` | viewer | List services for a scope/app. |
| `GET` | `/api/v1/inventory/hosts` | viewer | List hosts for a scope. |
| `GET` | `/api/v1/inventory/agents` | viewer | List agents for a host. |
| `GET` | `/api/v1/inventory/topology` | viewer | Load dashboard topology. |
| `POST` | `/api/v1/inventory/companies` | admin | Create/update a company. |
| `PATCH` | `/api/v1/inventory/companies/{id}` | admin | Edit a company display name and slug. |
| `POST` | `/api/v1/inventory/sites` | admin | Create/update a site project, environment, app, and service. |
| `PATCH` | `/api/v1/inventory/projects/{id}` | admin | Edit a site/project display name and slug. |
| `PATCH` | `/api/v1/inventory/environments/{id}` | admin | Edit an environment display name and slug. |
| `PATCH` | `/api/v1/inventory/apps/{id}` | admin | Edit an app display name, slug, and platform kind. |
| `PATCH` | `/api/v1/inventory/services/{id}` | admin | Edit a service display name, slug, and role. |
| `POST` | `/api/v1/inventory/nodes` | admin | Create a node and return the generated wire config sample. Returns `409` if the agent id is already provisioned with a wire public key. |
| `PATCH` | `/api/v1/inventory/hosts/{id}` | admin | Edit a node/host slug, hostname, region, and visible labels. |
| `PATCH` | `/api/v1/inventory/agents/{id}` | admin | Edit an attached agent node id and version label. |
