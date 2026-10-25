# Dashboard Tracker

## Done

- Modular React dashboard structure under `dashboard/src/dashboard`.
- Light main workspace with dark collapsible sidebar.
- Overview company cards with site summaries.
- Overview, nodes, issues, issue detail, signals, traffic, bots/crawlers, browser scripts, deployments, and settings views.
- Issue detail tabs for overview, evidence, timeline, comments, related issues, and LLM analysis.
- Finding actions for status changes, file ignores, script allowlists, model analysis, and reports.
- Issue detail report tab with deterministic guidance, latest model section, copy, download, and generate-analysis actions.
- Operator guidance from Hub `operator_action` metadata: primary action, acknowledge criteria, escalation criteria, and checklist.
- Dashboard wording now uses `Acknowledged` instead of the confusing `Triaged` label.
- Reusable empty/loading/error states and tighter mobile behavior for issue detail, tabs, actions, and panels.
- Settings tabs for profile, Hub scope, triage defaults, companies, sites, nodes, users/2FA, and inventory.
- Static, React, and Node.js app kinds are available in site create/edit flows and labels.
- Profile push notification controls with browser support/config/permission/subscription state.
- Site icons/favicons where available.
- Lazy, request-level traffic views with parsed User-Agent families, bot/tool classification, cached IP intelligence, and explicit trusted/blocked IP policy.
- Company, site, and standalone report pages removed; inventory management remains in Settings and finding reports remain inside Issue Details.
- Deployment markers reduced to app-scoped, context-only records that cannot acknowledge, suppress, or downgrade findings.

## Next

- Validate the dashboard against a live Hub with all local agents running.
- Validate push opt-in against a served Hub URL with HTTPS or localhost.

## Later

- More dashboard customization for small teams.
