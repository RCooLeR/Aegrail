# Dashboard

Status: folded into the canonical docs spine

The dashboard plan now lives in:

- [Architecture](02_ARCHITECTURE.md): runtime-app boundaries
- [Detection And Correlation](05_DETECTION_AND_CORRELATION.md): triage views and finding behavior
- [Operations And Security](07_OPERATIONS_AND_SECURITY.md): dashboard authentication and safety
- [Delivery Plan](08_DELIVERY_PLAN.md): dashboard implementation phase

The target dashboard remains TypeScript, React, and Bootstrap, backed by Hub HTTP APIs.

Current Hub API slice:

- `GET /api/v1/findings?org=...&project=...&environment=...&app=...&limit=...`
- `GET /api/v1/rules?category=...&platform=...`
- `PATCH /api/v1/findings/{id}/status?org=...&project=...&environment=...`
- `POST /api/v1/findings/{id}/browser-script-allowlist?org=...&project=...&environment=...&app=...`
- `GET /api/v1/timeline?org=...&project=...&environment=...&app=...&since=...&limit=...`
- `GET /api/v1/coverage?org=...&project=...&environment=...&app=...&since=...&limit=...`
- `GET /api/v1/deployments?org=...&project=...&environment=...&app=...`
- `GET /api/v1/browser/scripts?org=...&project=...&environment=...&app=...&page=...&kind=...&since=...&limit=...`
- `GET /api/v1/browser/script-allowlist?org=...&project=...&environment=...&app=...&page=...&kind=...&status=...`
- `POST /api/v1/browser/script-allowlist?org=...&project=...&environment=...&app=...`
- `PATCH /api/v1/browser/script-allowlist/{id}/status?org=...&project=...&environment=...&app=...`
- `GET /api/v1/inventory/topology?org=...&project=...&environment=...`
- `GET /api/v1/inventory/apps?org=...&project=...&environment=...`
- `GET /api/v1/inventory/services?org=...&project=...&environment=...&app=...`
- `GET /api/v1/inventory/hosts?org=...&project=...&environment=...`
- `GET /api/v1/inventory/agents?org=...&project=...&environment=...&host=...`

These endpoints are the first backend surface for the future Findings, Timeline, Coverage, Inventory, Deployments, and Browser Scripts views. Rule metadata is exposed for consistent labels, versions, categories, and action hints. Finding status actions now support `open`, `acknowledged`, `false_positive`, and `resolved`. Browser allowlist actions can create reviewed entries, toggle them between `active` and `disabled`, and create entries directly from browser drift findings.
