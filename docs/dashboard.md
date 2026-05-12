# Aegrail Dashboard Plan

Status: planned
Date: 2026-05-12

The dashboard should be a read-first operating console for the Aegrail Hub. It must make distributed evidence understandable without replacing the CLI.

## Product Shape

Recommended stack:

- TypeScript
- React
- Bootstrap
- Hub HTTP API served by the Go binary

The dashboard should live in the same repo as a separate runtime app, for example:

```text
dashboard/
  package.json
  src/
app/
  cmd/aegrail/
  internal/adapters/http/
```

The Go Hub owns evidence, inventory, auth, and APIs. The React app owns presentation and operator workflow.

## Primary Workflows

The first dashboard should answer five questions quickly:

- What is happening right now?
- Which sites and hosts are monitored?
- Which findings need attention?
- What evidence supports this finding?
- Did this happen during a deployment or outside normal change windows?

## Information Architecture

```text
Dashboard
  Overview
  Findings
  Timeline
  Inventory
  Sites
  Agents
  Browser Scripts
  Deployments
  Reports
  Settings
```

## Overview

The overview is the first screen for daily use:

- active high and critical findings
- newest incident chains
- event ingest rate
- agents offline or delayed
- sites with missing coverage
- recent deployments
- browser script drift
- database-sensitive changes

This page should be dense and operational, not a marketing landing page.

## Findings

Finding list filters:

- organization
- project
- environment
- app/site
- service
- host
- severity
- status
- rule ID
- time window

Finding detail should show:

- finding summary
- severity and confidence
- evidence timeline
- affected hosts/sites
- related deployments
- related file, log, database, and browser events
- raw evidence references, with sensitive values redacted
- actions: acknowledge, mark false positive, export, create allowlist item where applicable

## Timeline

The timeline is the core evidence view.

Filters:

- time window
- org/project/environment
- app/site
- service
- host
- agent
- event type
- severity
- source

Event rows should make the distributed context visible:

```text
19:04:11  production  example-com  web-02  file.created  high  /wp-content/uploads/avatar.php
19:04:30  production  example-com  db-01   db.role_changed high  user 42 editor -> admin
19:05:10  production  example-com  worker-01 cron.created medium php /tmp/task.php
```

## Inventory

Inventory views should show the Hub hierarchy:

```text
Organization
  Project
    Environment
      App / Site
        Service
          Host
            Agent
```

Each app/site detail page should show:

- monitored roots
- configured logs
- configured databases
- browser crawl seeds
- latest file baseline status
- latest database snapshot status
- latest browser crawl status
- active findings
- recent timeline
- deployed version or commit when available

## Agents

The agent page should show:

- agent ID
- host
- version
- fingerprint
- last seen
- queue health
- pending/sent/failed batch counts
- configured sites
- coverage gaps
- clock skew hints
- latest error messages

For a shared server, this page must clearly show all sites monitored by that one agent.

## Browser Scripts

This view tracks JavaScript loaded by public pages:

- page URL
- observed external script domains
- observed script URLs
- inline script hashes
- tag manager IDs
- first seen / last seen
- drift from baseline
- allowlist status

Operators should be able to approve a known-good domain, inline hash, or tag manager ID from a reviewed finding.

## Configuration Coverage

The dashboard should eventually show config coverage from multi-site agents:

```text
example.com
  Files: wordpress profile, healthy
  Logs: nginx access, PHP debug
  DB: configured, last snapshot 5m ago
  Browser: rendered crawl, last crawl 12m ago

example2.com
  Files: prestashop profile, healthy
  Logs: missing
  DB: configured, last snapshot 9m ago
  Browser: disabled
```

This makes misconfiguration visible before an incident.

## API Surface

Initial read endpoints:

```text
GET /api/v1/healthz
GET /api/v1/inventory/orgs
GET /api/v1/inventory/projects
GET /api/v1/inventory/environments
GET /api/v1/inventory/apps
GET /api/v1/inventory/hosts
GET /api/v1/inventory/agents
GET /api/v1/events
GET /api/v1/findings
GET /api/v1/findings/{id}
GET /api/v1/deployments
GET /api/v1/browser/scripts
GET /api/v1/reports
```

Initial write endpoints:

```text
POST /api/v1/findings/{id}/acknowledge
POST /api/v1/findings/{id}/false-positive
POST /api/v1/browser/scripts/allowlist
POST /api/v1/reports
```

The dashboard should not duplicate rule logic. It should call Hub use cases through HTTP handlers.

## Authentication Direction

First local version:

- single admin user or reverse-proxy basic auth
- secure cookies for browser sessions
- no public unauthenticated dashboard

Later:

- users and roles
- read-only analyst role
- admin role for allowlists and settings
- audit log for dashboard actions

## Data Safety

The dashboard should default to redacted values:

- query tokens
- cookies
- authorization headers
- database passwords
- API keys
- personally sensitive values where possible

Raw evidence should be behind an explicit reveal/export path, not visible on ordinary list screens.

## First Implementation Steps

1. Add read APIs for Hub inventory, events, findings, deployments, and browser script observations.
2. Add a `dashboard/` React app with Bootstrap and API client plumbing.
3. Build Overview, Findings, Timeline, Inventory, Agents, and Browser Scripts views.
4. Add finding actions for acknowledge and browser allowlist handoff.
5. Add config coverage once multi-site agent config reporting exists.
