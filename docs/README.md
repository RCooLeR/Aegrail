# Aegrail Documentation

This directory contains the maintained project documentation. Keep implementation notes, runbooks, design decisions, and tracker items here instead of adding loose markdown files at the repository root.

## Start Here

- [Project Overview](overview.md): what Aegrail is, runtime model, and data hierarchy.
- [Agent And Evidence Internals](agent.md): collectors, schedules, exact database queries, hashes, queue format, signing, and Hub ingest.
- [Dashboard](dashboard.md): dashboard purpose, views, scripts/deployments workflows, settings, and local development commands.
- [Local Runbook](runbook.md): local PostgreSQL, Hub, CLI, and report commands.
- [Security And Data Handling](security.md): privacy, redaction, transport, storage, and operating checklist.
- [Development Notes](development.md): engineering standards and verification commands.
- [Project Tracker](tracker.md): current status, next work, and later roadmap.
- [Brand Assets](brand/README.md): logos and visual assets.

## Maintenance Rules

- Keep docs generic. Do not include real customer paths, domains, DSNs, secrets, local queue data, or environment dumps.
- Prefer updating these maintained documents over adding one-off markdown notes.
- If a topic grows too large, split it into a named file in `docs/` and link it from this index.
- Update the tracker when behavior or project status changes.
