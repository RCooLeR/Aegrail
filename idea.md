# Aegrail Project Idea

## Summary

Aegrail is a lightweight security-audit and anomaly-detection tool for small and medium websites, ecommerce shops, and self-hosted applications. It periodically downloads logs, database audit tables, configuration snapshots, and file-change metadata from multiple sites, then detects suspicious activity using deterministic rules, baselines, and LLM-assisted investigation summaries.

The goal is not to let an LLM read millions of raw log lines directly. The reliable core should be written in Go and should parse, normalize, redact, aggregate, and score events first. The LLM is used after that to correlate findings, explain timelines, classify likely incident paths, and generate readable reports for technical and non-technical stakeholders.

## Problem

Many smaller sites do not have a proper SIEM, SOC, or managed detection service. Incidents are often discovered only after customers report browser warnings, antivirus alerts, payment problems, or strange site behavior.

Common blind spots include:

- back-office logins from new IPs, countries, ASNs, VPNs, or Tor exits
- new administrator users
- unexpected module/plugin installs
- malicious JavaScript injected into database configuration
- customer CSV exports
- uploaded PHP files under writable folders
- modified payment, email, or checkout configuration
- access logs that show suspicious admin activity but are too noisy to inspect manually
- code files that changed outside a normal deployment process

Aegrail should make these signals visible early and turn them into a clear timeline.

## Target Users

- agencies maintaining multiple ecommerce sites
- small companies running PrestaShop, WordPress, WooCommerce, Magento, or custom PHP applications
- developers responsible for several client sites
- incident responders who need quick triage from raw logs and database dumps
- hosting administrators who want lightweight daily security summaries

## Core Principle

Use deterministic logic for detection and use the LLM for explanation.

Good:

- parse logs into structured events
- compare current state against previous baselines
- run clear security rules
- redact sensitive fields
- send compact suspicious-event bundles to the LLM
- produce human-readable reports

Avoid:

- sending raw unredacted logs directly to an LLM
- relying on the LLM as the only detector
- storing credentials or customer data unnecessarily
- generating high-confidence claims without evidence references

## High-Level Architecture

```text
Sites
  -> Collectors
  -> Normalizers
  -> Redaction
  -> Storage
  -> Rule Engine
  -> Baseline Diff Engine
  -> Risk Scoring
  -> LLM Investigation Layer
  -> Alerts / Reports / Dashboard
```

## Components

### 1. Collectors

Collectors fetch evidence from each monitored site.

Possible collector types:

- SSH/SFTP log downloader
- rsync snapshot collector
- HTTP endpoint collector with signed token
- database dump importer
- MySQL read-only query collector
- git repository diff collector
- hosting panel export importer
- manual upload/import mode for incident response

Initial supported sources:

- Nginx access logs
- Apache access logs
- PHP error logs
- application logs
- PrestaShop database tables
- file modification inventory
- git status/diff output

### 2. Normalizers

Normalizers convert raw sources into a shared event model.

Example event fields:

```text
id
site_id
timestamp
source_type
source_file
actor_type
actor_id
actor_email
ip
method
path
query
controller
action
status_code
bytes
user_agent
object_type
object_id
event_name
risk_tags
raw_ref
```

The normalized event model lets Aegrail correlate database events, access-log requests, and file changes in one timeline.

### 3. Redaction

Redaction must happen before LLM analysis and before exporting reports.

Sensitive data to redact:

- passwords
- password reset tokens
- session IDs
- cookies
- API keys
- payment credentials
- SMTP credentials
- customer names, emails, phones, and addresses unless explicitly needed
- full query strings that contain tokens

The system should preserve useful security shape while removing secrets.

Example:

```text
Original:
GET /admin/index.php?token=abc123&controller=AdminSecurityManager&action=DownloadBuyersCsv

Redacted:
GET /admin/index.php?token=[REDACTED]&controller=AdminSecurityManager&action=DownloadBuyersCsv
```

### 4. Storage

MVP storage can be SQLite for single-user/local usage.

Future storage options:

- PostgreSQL for multi-site/multi-user deployments
- object storage for raw evidence archives
- compressed local evidence bundle per site/day

Important tables:

- sites
- evidence_imports
- normalized_events
- detected_findings
- file_snapshots
- db_snapshots
- baselines
- llm_reports
- alert_deliveries

### 5. Rule Engine

Rules should be simple, explainable, and testable.

Example rules:

- admin login from Tor exit node
- admin login from new IP, country, ASN, or impossible travel
- new administrator account
- administrator profile changed to SuperAdmin
- unexpected module/plugin installed
- database configuration contains `<script`
- database configuration references unknown external JavaScript
- PHP file appears under upload/image/cache folders
- customer export endpoint called
- payment configuration changed
- sudden spike in 404, 500, POST, or admin requests
- repeated login attempts from one IP
- access to known webshell filenames
- suspicious PHP functions appear in new or changed files

Each rule should produce:

```text
finding_id
severity
confidence
title
description
evidence_refs
recommended_next_check
```

### 6. Baseline Diff Engine

The baseline engine compares snapshots over time.

Examples:

- Apr 19 DB vs Apr 26 DB
- previous clean code snapshot vs current server files
- yesterday's employees vs today's employees
- previous module list vs current module list
- previous config values vs current config values

Useful DB diff categories:

- new users/admins
- changed passwords or password timestamps
- changed permissions/profiles
- new modules/plugins
- changed module active states
- new hook registrations
- changed configuration values
- new suspicious tabs/controllers
- customer/order/payment anomalies

Useful file diff categories:

- new executable files
- changed tracked files
- deleted tracked files
- new files in writable directories
- files with risky PHP functions
- files with obfuscation patterns
- unexpected archives
- unexpected `.htaccess` changes

### 7. Reputation Enrichment

Optional enrichment can add context to IPs and domains.

Potential enrichment sources:

- Tor exit consensus archives
- ASN lookup
- GeoIP
- known cloud providers
- threat-intel feeds
- domain age / WHOIS where available
- blocklists

Enrichment should be cached and should never be the only reason for a high-severity alert.

### 8. LLM Investigation Layer

The LLM receives compact evidence bundles, not raw logs.

Example LLM input:

```text
Site: example.com
Window: 2026-04-22 21:45 to 2026-04-27 20:00

High-risk findings:
- Employee 4 login from Tor IP at 21:52
- Employee 18 first seen at 22:03 from Tor IP
- New SuperAdmin employees 18-25 appeared between baseline A and B
- SecurityManager module used to download buyers CSV
- Custom JS config later updated with external script URL

Task:
Build a concise incident timeline, likely compromise path, confidence levels, and next evidence to collect.
```

LLM outputs:

- incident timeline
- executive summary
- technical report
- likely root cause hypotheses
- evidence gaps
- cleanup checklist draft
- notification-ready data exposure summary

The UI should label LLM output as analysis/synthesis and keep deterministic evidence separately visible.

## PrestaShop-Specific MVP

PrestaShop is a good first target because the high-risk signals are concrete.

Initial PrestaShop tables:

- `ps_employee`
- `ps_employee_session`
- `ps_log`
- `ps_configuration`
- `ps_module`
- `ps_module_shop`
- `ps_hook`
- `ps_hook_module`
- `ps_tab`
- `ps_access`
- `ps_connections`
- order/payment tables for anomaly checks

Initial PrestaShop detections:

- new employee accounts
- employee profile changes
- logins from new IPs
- logins from Tor/VPN/cloud hosting
- rogue SuperAdmin users
- suspicious module install/import/configuration
- external script in config values
- customer CSV export endpoints
- back-office actions followed by file changes
- unexpected modules with admin controllers
- changed payment/email/shipping configuration

## Example Alert

```text
Severity: Critical
Title: Rogue administrator activity and customer export

Evidence:
- New SuperAdmin employee support@example.invalid appeared after clean baseline.
- First login was from Tor exit IP.
- Same employee called DownloadBuyersCsv and received a 5.4 MB response.
- Related module did not exist in clean baseline.

Assessment:
Treat as likely back-office compromise and personal-data exposure.

Next checks:
- Compare DB snapshots around account creation time.
- Check access logs for admin endpoints in same session.
- Check server files for modules added during the same window.
```

## MVP Scope

Build a CLI-first Go application:

```text
aegrail init
aegrail site add
aegrail import logs --site petlink --path ./logs
aegrail import prestashop-db --site petlink --dump ./dump.sql --snapshot 2026-05-11
aegrail diff db --site petlink --from 2026-04-19 --to 2026-05-11
aegrail scan files --site petlink --path ./files
aegrail analyze --site petlink --since 2026-04-22
aegrail report --site petlink --format md
```

MVP outputs:

- Markdown technical report
- Markdown manager summary
- JSON findings file
- CSV timeline
- optional HTML dashboard later

## Suggested Tech Stack

- Go for collectors, parsers, rules, CLI, and local server
- SQLite for MVP storage
- PostgreSQL later for multi-site deployment
- Cobra or urfave/cli for CLI
- Bubble Tea optional for terminal UI
- DuckDB optional for large log analytics
- OpenTelemetry-style event naming if useful
- Pluggable LLM provider interface
- Local LLM support for privacy-sensitive deployments

## Security Requirements

Aegrail will handle sensitive incident data, so it should be conservative.

Required:

- encrypt stored credentials
- support read-only database users
- redact secrets before LLM calls
- keep raw evidence local by default
- support offline/local-only mode
- write immutable evidence import manifests
- hash imported files
- record tool version and rule version for each report
- avoid modifying monitored sites unless explicitly configured

## Report Types

### Daily Health Report

Short summary:

- no high-risk findings
- notable admin logins
- module/config changes
- traffic anomalies
- files changed

### Incident Triage Report

For active investigations:

- timeline
- affected accounts
- suspicious IPs/domains
- malicious files/configs
- data exposure evidence
- confidence levels
- evidence gaps

### Manager Brief

Non-technical:

- what happened
- when it likely started
- whether data exposure occurred
- current confidence
- what is still being investigated

## Future Ideas

- multi-tenant web dashboard
- Slack/Teams/email alerts
- YARA/Sigma-like rule format
- plugin system for WordPress/WooCommerce/Magento
- git integration for known-good code comparison
- automatic IOC extraction
- incident graph visualization
- scheduled evidence collection
- local LLM incident analyst mode
- one-click evidence bundle export
- integration with backup systems
- integration with WAF/CDN logs

## Success Criteria

Aegrail is useful if it can answer these questions quickly:

- Did any admin account behave strangely?
- Did any new privileged users appear?
- Did site configuration change in a dangerous way?
- Did code files change outside deployment?
- Was customer data exported?
- What happened first?
- What evidence supports the conclusion?
- What should be investigated next?

