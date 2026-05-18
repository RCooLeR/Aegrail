# Aegrail Documentation

This directory contains the maintained project documentation. Keep implementation notes, runbooks, design decisions, and tracker items here instead of adding loose markdown files at the repository root.

## Start Here

- [How Aegrail Works](../how-it-works.md): full-system architecture, data flow, and operational model.
- [Agent](agent/README.md): what the Agent owns and where to install/run it.
- [Hub](hub/README.md): Hub storage, APIs, rules, reporting, users, and model analysis.
- [Dashboard](dashboard/README.md): dashboard purpose, views, operator flows, and frontend structure.
- [Services](services/README.md): local PostgreSQL, Redis, and development infrastructure.
- [Docker Examples](../docker/examples/README.md): example Hub and Agent images plus compose files.
- [Security And Data Handling](security.md): privacy, redaction, transport, storage, and operating checklist.
- [Development Notes](development.md): engineering standards and verification commands.
- [Project Tracker](tracker.md): cross-project status and links to app-specific trackers.
- [Brand Assets](brand/README.md): logos and visual assets.

## App Docs

```text
docs/agent/       Agent docs: install, internals, tracker.
docs/hub/         Hub docs: install, internals, Agent API, Dashboard API, tracker.
docs/dashboard/   Dashboard docs: install, UI model, tracker.
docs/services/    Local service docs: PostgreSQL, Redis, and Compose setup.
docs/brand/       Brand assets and favicon/logo notes.
docker/examples/  Example Hub and Agent Dockerfiles, Compose files, and env/config templates.
```

## Maintenance Rules

- Keep docs generic. Do not include real customer paths, domains, DSNs, secrets, local queue data, or environment dumps.
- Prefer updating these maintained documents over adding one-off markdown notes.
- If a topic grows too large, split it into a named file in `docs/` and link it from this index.
- Update the tracker when behavior or project status changes.
