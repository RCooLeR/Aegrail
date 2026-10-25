# Project Tracker

This is the cross-project tracker. App-specific details live in:

- [Agent Tracker](agent/tracker.md)
- [Hub Tracker](hub/tracker.md)
- [Dashboard Tracker](dashboard/tracker.md)

## Done

- Split the old combined Go module into independent `hub/` and `agent/` modules with separate `go.mod`, configs, commands, and internal packages.
- Established the documentation structure by app area: Agent, Hub, Dashboard, Services, plus root system docs.
- Local PostgreSQL, Redis queue/lock service, and migrations.
- Signed Agent-to-Hub ingest.
- Encrypted Agent-Hub wire v1 with Hub-generated node config samples.
- Dashboard/Hub creation flow for companies, sites, and nodes.
- Distributed inventory: organizations, projects, environments, apps, services, hosts, and agents.
- Modular React dashboard with operational overview, nodes, issue detail, signals, traffic, bots/crawlers, scripts, context-only deployments, and settings.
- Deterministic rules, Redis-backed ingest correlation, finding lifecycle, baseline acceptance, ignore/allowlist workflows, reports, and optional model analysis.
- Mautic, Yii2 RBAC, Laravel, static, React, and Node.js support in Agent collectors, Hub rules, and model-analysis prompt context.
- Admin login POST and password-reset request monitoring from normalized access logs.
- Agent access-log classification retains routine public, API, and static requests for the typed traffic projection while keeping them out of the security timeline and correlation; admin/login/reset, Tor, client-error, server-error, and direct PHP evidence remains high signal.
- Browser crawler uses a named Aegrail bot identity, compatibility fallbacks, and redacted browser URL/attribute payloads.
- Email notifications through SMTP and browser push notifications through VAPID/web push subscriptions.
- Added Docker examples for packaging Hub and Agent with ignored env/config templates.

## Next

- Tighten default noise rules for cache/upload/generated paths as more real projects are profiled.
- Improve report comparison between deterministic findings and model analysis.
- Add production rollout runbooks for starting Hub plus one Agent at a time.

## Later

- Provider-hosted collectors.
- Scheduled Hub-side jobs.
- Per-agent secrets or mTLS.
- Audit log and retention settings.
