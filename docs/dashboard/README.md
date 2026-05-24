# Dashboard

The dashboard is for quick operational judgement.

It should answer:

- is everything healthy?
- if not, which company, site, node, service, or issue needs attention?
- what evidence supports the issue?
- can the operator mark it reviewed, resolved, or false positive?
- can the operator generate a useful report?

## Views

- Overview: up to six companies sorted by severity, with site summaries.
- Companies: all companies and health counts.
- Sites: company/site drilldown.
- Nodes: instances, agents, services, and issue actions.
- Issues: active queue with details, evidence, action buttons, and report export.
- Issue Details: overview, evidence, timeline, comments, related issues, and LLM analysis generation.
- Signals: readable raw observations for debugging.
- Browser Scripts: script observations, domains, inline hashes, tag-manager IDs, and allowlist actions.
- Deployments: mark a confirmed deployment timeframe after previewing open alerts/warnings in that window.
- Reports: deterministic and model-assisted reports.
- Settings: tabbed profile, Hub scope, triage defaults, companies, sites, nodes, users/access/2FA, and inventory.

The main dashboard surface should stay simple: show what is wrong, where, why, and what action can be taken.

## Docs

- [Install](install.md): local development server, production build, and Hub static serving.
- [Tracker](tracker.md): dashboard status, next work, and later work.
- [Hub Dashboard API](../hub/dashboard-api.md): API routes consumed by the dashboard.

## Structure

```text
src/App.tsx                  composition root
src/dashboard/controllers/   data loading and actions
src/dashboard/model/         view models and sorting
src/dashboard/pages/         dashboard pages
src/dashboard/components/    shared UI pieces
src/dashboard/utils/         formatting, reports, metadata helpers
```

Rules:

- Detection logic belongs in the Hub, not in browser code.
- Dashboard pages should read Hub APIs and present clear operator actions.
- Issue views should explain why a warning exists and what action is expected.
- The LLM analysis action sends only the selected issue's compact redacted evidence bundle to the configured model gateway, then stores the returned advisory report with prompt and evidence hashes.
- The model returns strict JSON. Hub converts that JSON into escaped, controlled HTML for the dashboard; raw model HTML is not trusted.
- Hub can also analyze the issue queue automatically. `hub serve` starts a background pass by default, controlled by `AEGRAIL_MODEL_ANALYSIS_AUTO`, `AEGRAIL_MODEL_ANALYSIS_INTERVAL`, and `AEGRAIL_MODEL_ANALYSIS_LIMIT`. Keep the limit small for local GPUs.
- Operators can run one pass manually from `hub/` with `go run ./cmd/hub model-analysis queue`.
- The Deployments page records a version/note, actor, optional commit SHA, start time, and finish time. It previews open issues that overlap the selected node/timeframe and requires a second confirmation before saving.
- Deployment markers acknowledge already-open expected deployment findings in that window and suppress future expected file/browser drift for the same window. High-risk administrator, payment, sensitive config, writable PHP, persistence, and incident-chain findings stay visible.
- The Browser Scripts page can allowlist a domain, inline SHA-256, or tag-manager ID. It updates Hub allowlist state; it does not edit agent YAML.
- Users & 2FA uses a pending enrollment flow: generate QR, verify the current 6-digit TOTP code, then activate. Dashboard access stays locked until the current user has active 2FA.
- Browser-to-Hub calls use `aegrail.dashboard.v1`: HttpOnly session cookie for authentication, `X-Aegrail-Dashboard-Protocol` on dashboard requests, and `X-Aegrail-CSRF` on mutating requests.
- Profile settings can enable browser push notifications when the Hub has VAPID keys configured. The dashboard registers `aegrail-sw.js`, stores the current browser subscription in Hub, and can disable it again from the same panel.
- File issues can create Hub ignore rules for a directory. The dashboard prompts for the path, the Hub suppresses future matching file findings, and the selected issue is marked false positive.
- Node details show a safe agent config snapshot from config coverage, including collector state, database/log/browser counts, and sanitized file paths ignored by the agent.
- Settings can create companies, sites, and nodes. Node creation generates an `aegrail.agent.wire.v1` node ID/secret pair and shows a ready-to-edit Agent YAML sample.
