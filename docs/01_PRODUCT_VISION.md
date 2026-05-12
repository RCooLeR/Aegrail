# Product Vision

## One-Line Vision

Aegrail is the evidence-first monitoring and incident triage platform for WordPress, PrestaShop, and PHP application estates.

## Problem

Small and mid-sized websites are often spread across shared servers, VPS hosts, managed WordPress platforms, ecommerce stacks, staging copies, worker nodes, and database hosts. When something goes wrong, the evidence is scattered:

- suspicious files may appear on only one web node
- admin logins may be visible only in access logs
- role changes live in the database
- JavaScript injections may be hidden inside page builders, tag managers, widgets, or CMS content
- cron persistence can happen outside the main web root
- deployments create legitimate noise that looks like tampering unless the system knows a deploy is happening

Most teams do not need a generic enterprise SIEM first. They need a focused product that understands how real PHP websites get compromised and can preserve enough evidence to explain what happened.

Aegrail solves this by combining local agents, central Hub storage, CMS-aware collectors, deterministic rules, browser JavaScript monitoring, and source-grounded reports.

## Target Users

- Agencies responsible for many WordPress and PrestaShop sites.
- Server administrators running many virtual hosts on one machine.
- Ecommerce maintainers who need to detect admin, module, and payment-setting changes.
- Security consultants doing incident triage for client sites.
- Developers responsible for PHP applications and deployments.
- Site owners who need clear technical and non-technical reports.

## Product Experience

Aegrail should feel like a calm incident desk:

- agents collect evidence quietly and keep working offline when the Hub is unreachable
- the Hub builds a clean cross-host timeline
- findings explain why something matters and what evidence supports it
- dashboard views make coverage gaps obvious before an incident
- reports are useful to both developers and managers
- Ollama-based synthesis helps explain deterministic findings without replacing them

The CLI remains first-class. The dashboard should make daily review, triage, and reporting easier, not hide how the system works.

## What Makes Aegrail Different

1. Evidence-first monitoring

   Aegrail stores normalized events, snapshots, file hashes, log-derived evidence, browser observations, and database changes before asking an LLM to summarize anything.

2. CMS-aware detection

   WordPress and PrestaShop are first-wave targets. Aegrail should understand administrators, user capabilities, options, plugins, themes, cron, employees, modules, configuration, hooks, tabs, and sensitive settings.

3. Distributed incident timelines

   Multiple agents can report into one Hub. Aegrail can correlate login activity, file changes, database changes, cron persistence, browser script drift, and deployments across hosts.

4. Multi-site server configuration

   One agent should monitor many hosted sites on the same server while emitting clean per-site app and service context.

5. Browser JavaScript visibility

   Aegrail should crawl public pages, wait for bounded rendered-page behavior, observe tag-manager-loaded scripts, and detect drift in external domains, script URLs, inline hashes, and tag manager IDs.

6. Local-first AI

   Ollama on local GPU hardware can generate readable incident analysis from redacted evidence bundles. Deterministic evidence remains the authority.

## Success Criteria

- One `aegrail` binary can run Local, Hub, Agent, and Collector workflows.
- A single server agent can monitor many site roots, logs, databases, and crawl seeds from a versioned config.
- Events always carry organization, project, environment, app, service, host, agent, region, and labels where known.
- File changes under writable PHP paths, plugin/module changes, role changes, and suspicious options/configuration become deterministic findings.
- Browser crawl observations detect new script domains, inline hashes, and tag manager IDs.
- Deployment windows reduce false positives without hiding suspicious out-of-band changes.
- The Hub dashboard shows findings, timelines, inventory, agent health, coverage gaps, browser script drift, deployments, and reports.
- Reports include evidence references, rule versions, model names, prompt versions, and redaction behavior.
- Aegrail can run locally with PostgreSQL, pgvector, and Ollama while keeping a path to scaled workers later.

## MVP Scope Guardrails

Do not build everything at once.

Protect the core:

- collect trustworthy evidence
- normalize events consistently
- detect high-signal WordPress and PrestaShop compromise patterns
- correlate across hosts and services
- keep secrets out of reports and prompts
- make the system easy to run and inspect

Everything else should support those outcomes.
