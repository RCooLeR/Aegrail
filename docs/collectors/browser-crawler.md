# Browser Crawler And JavaScript Monitoring Plan

Status: in progress; static and rendered script inventory implemented
Date: 2026-05-12

Canonical context:

- [Evidence Collection](../04_EVIDENCE_COLLECTION.md)
- [Detection And Correlation](../05_DETECTION_AND_CORRELATION.md)
- [Delivery Plan](../08_DELIVERY_PLAN.md)

## Goal

Aegrail should include a lightweight browser crawler collector that renders selected public pages and records the JavaScript actually loaded by the browser. This is needed for WordPress page builders, injected widgets, tag managers, compromised options, and malicious third-party scripts that are not visible from server-side file or database snapshots alone.

The first version should be small and practical:

```text
seed URLs
  -> render in headless browser
  -> wait for page and tag-manager scripts to settle
  -> collect script inventory and network evidence
  -> compare against baseline
  -> emit Hub events/findings
```

## Why A Simple HTTP Fetch Is Not Enough

Many risky scripts are added after the initial HTML response:

- Google Tag Manager or another tag manager injects scripts.
- WordPress page builders render late widgets.
- consent/cookie tools inject marketing scripts after startup.
- compromised options/widgets add inline JavaScript.
- third-party checkout, chat, analytics, or ad code loads follow-up scripts.

Aegrail needs a real browser mode, not only `GET /page` parsing.

## Collector Shape

The collector should live under the generic `collector` runtime app, with WordPress-aware presets:

```text
aegrail collector browser crawl --url https://example.com --format json
aegrail collector browser crawl --url https://example.com --rendered --wait-tag-manager --timeout 30s --format json
aegrail collector browser crawl --url https://example.com --rendered --ingest --org acme --project customer-site --env production --app main-web --service frontend --host web-01 --agent-id agt_web_01
aegrail hub correlate browser-scripts --org acme --project customer-site --env production --app main-web --baseline 30d --since 24h --save
aegrail hub browser-scripts allow --org acme --project customer-site --env production --app main-web --page https://example.com --kind domain --value trusted-chat.example --reason "approved chat vendor"
aegrail hub browser-scripts allowlist --org acme --project customer-site --env production --app main-web
aegrail collector browser crawl --url https://example.com --url https://example.com/contact --max-pages 10
```

Current implementation:

- fetches supplied HTTP/HTTPS URLs
- parses initial HTML in static mode
- can use an installed Chrome/Chromium browser in rendered mode through Chrome DevTools Protocol
- resolves external script URLs
- redacts sensitive query parameters
- hashes inline script bodies
- detects obvious Google Tag Manager and Google tag IDs
- records browser network metadata for rendered script responses when available
- supports bounded rendered waits with `--network-idle`, `--settle`, and `--wait-tag-manager`
- can save crawl observations as normalized Hub ingest events with `--ingest`
- can compare Hub browser event history with `hub correlate browser-scripts` to save drift findings
- can approve known-good drift values with `hub browser-scripts allow`
- outputs table or JSON

Next rendered-browser work:

- Store only normalized script evidence by default, not full page content.
- Hash inline script bodies and fetched script responses.
- Redact query strings and obvious tokens from URLs.
- Add finding-to-allowlist handoff helpers once finding IDs have richer detail views.

## What To Capture

Per crawl run:

- crawl ID
- page URL
- final URL after redirects
- status code
- page title
- canonical URL when present
- detected CMS/page-builder hints
- timing milestones
- evidence coverage warnings

Per script:

- source type: `html`, `dom`, `network`, `inline`, `eval-like`
- script URL when external
- normalized domain
- redacted query
- response status and content type when fetched by browser
- SHA-256 of script response when available
- SHA-256 of inline script body
- script tag attributes such as `async`, `defer`, `type`, `integrity`, `nonce`, `crossorigin`
- initiator when available
- whether the script was present in initial HTML or injected later
- first observed time relative to navigation start

Per tag manager:

- detected container ID such as `GTM-...`
- scripts injected after tag manager load
- `dataLayer` events observed during the crawl when safe to record
- warning when the container is present but scripts did not settle before timeout

## Waiting Strategy

Yes: Aegrail should wait for tag-manager-loaded scripts, but bounded and configurable.

Default browser wait plan:

1. Navigate with Chrome/Chromium.
2. Wait for browser readiness.
3. Wait for network quiet, for example no relevant network activity for 2 seconds.
4. If tag-manager mode is enabled, wait for known tag-manager activity to settle.
5. Apply an extra settle delay, for example 2 to 5 seconds.
6. Stop at a hard timeout, for example 30 seconds, and record a coverage warning.

Suggested flags:

```text
--timeout 30s
--network-idle 2s
--settle 5s
--wait-tag-manager
--max-pages 10
--same-host-only
```

The collector should not wait forever. A timeout is still useful evidence if it says which scripts were seen before the cutoff.

## Baseline And Drift

The crawler should support baselines per app/environment/page:

```text
page: https://example.com/
expected script domains:
  - example.com
  - www.googletagmanager.com
  - www.google-analytics.com
  - trusted-chat.example
```

Suspicious changes:

- new script domain
- new inline script hash
- known plugin/page-builder script changed outside deployment
- script loaded from typo-squatted domain
- script loaded from raw IP address
- script loaded over plain HTTP on an HTTPS page
- script URL contains suspicious encoded payload
- tag-manager container changed
- tag-manager injected a new unapproved vendor
- same page differs between web nodes or environments

Baseline comparison should use normalized domains and hashes. Reports should show enough evidence to review the change without dumping full script bodies by default.

Approved drift values are stored in the Hub browser script allowlist. Entries can be scoped to one page or to the whole app when `--page` is omitted. Supported allowlist kinds are:

- `domain`
- `inline_hash`
- `tag_manager_id`

Allowlist entries can be managed from the CLI:

```bash
aegrail hub browser-scripts allow --org acme --project customer-site --env production --app main-web --kind domain --value cdn.vendor.example --reason reviewed --approved-by roman
aegrail hub browser-scripts status --org acme --project customer-site --env production --app main-web --id allowlist-id --status disabled --reason vendor-removed --approved-by roman
```

The dashboard-facing Hub API exposes the same workflow:

- `GET /api/v1/browser/script-allowlist`
- `POST /api/v1/browser/script-allowlist`
- `PATCH /api/v1/browser/script-allowlist/{id}/status`

## WordPress-Specific Value

WordPress-specific presets should seed:

- home page
- login page if intentionally allowed
- checkout/cart/account pages for WooCommerce when configured
- top menu URLs from a sitemap or user-provided list
- representative page-builder pages
- high-value landing pages

The crawler should look for hints from:

- Elementor
- Divi
- WPBakery/Visual Composer
- Gutenberg blocks
- WooCommerce
- common consent/tag/chat plugins

Findings should connect browser evidence back to WordPress DB/file evidence when possible. For example:

```text
wp_options changed active plugin
  -> browser crawl now loads new vendor script
  -> finding: plugin activation introduced new third-party JavaScript
```

## Hub Events

Initial event types:

- `browser.crawl.completed`
- `browser.script.observed`
- `browser.tag_manager.detected`
- `browser.coverage.warning`

Current baseline/drift finding rules:

- `browser-script-domain-new`
- `browser-inline-script-changed`
- `browser-tag-manager-id-new`

These events should carry the normal Hub labels:

- org
- project
- environment
- app
- service
- host or collector identity
- page URL
- region

## Open Questions

- Should the first implementation use a bundled Chromium dependency, an installed Chrome, or a remote browser endpoint?
- Should crawl results be stored as Hub ingest events only, or also as snapshot tables for faster baseline comparisons?
- How should authenticated pages be handled without storing browser cookies unsafely?
- Should Aegrail support customer-provided allowlists before the first crawl, or learn an initial baseline first and require review?
