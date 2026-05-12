# Dashboard

Status: folded into the canonical docs spine

The dashboard plan now lives in:

- [Architecture](02_ARCHITECTURE.md): runtime-app boundaries
- [Detection And Correlation](05_DETECTION_AND_CORRELATION.md): triage views and finding behavior
- [Operations And Security](07_OPERATIONS_AND_SECURITY.md): dashboard authentication and safety
- [Delivery Plan](08_DELIVERY_PLAN.md): dashboard implementation phase

The target dashboard remains TypeScript, React, and Bootstrap, backed by Hub HTTP APIs.

Current Hub read API slice:

- `GET /api/v1/findings?org=...&project=...&environment=...&app=...&limit=...`
- `GET /api/v1/timeline?org=...&project=...&environment=...&app=...&since=...&limit=...`
- `GET /api/v1/coverage?org=...&project=...&environment=...&app=...&since=...&limit=...`
- `GET /api/v1/inventory/topology?org=...&project=...&environment=...`
- `GET /api/v1/inventory/apps?org=...&project=...&environment=...`
- `GET /api/v1/inventory/services?org=...&project=...&environment=...&app=...`
- `GET /api/v1/inventory/hosts?org=...&project=...&environment=...`
- `GET /api/v1/inventory/agents?org=...&project=...&environment=...&host=...`

These endpoints are the first backend surface for the future Findings, Timeline, Coverage, and Inventory views. Deployments, browser-script observations, and finding actions are still planned.
