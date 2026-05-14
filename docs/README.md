# Aegrail Documentation

Aegrail is an evidence-first monitoring and incident triage platform for WordPress, PrestaShop, and PHP application estates.

## What this repository contains

- `app/` runtime and service code for Hub, Agent, Collector, and command tooling.
- `dashboard/` React dashboard application that consumes Hub APIs.
- `services/` local services for development and parity testing.
- `data/` runtime state and local sample data directories.

## Documentation

### Core documentation

- [Product Vision](01_PRODUCT_VISION.md)
- [Architecture](02_ARCHITECTURE.md)
- [Domain Model](03_DOMAIN_MODEL.md)
- [Evidence Collection](04_EVIDENCE_COLLECTION.md)
- [Detection And Correlation](05_DETECTION_AND_CORRELATION.md)
- [AI And LLM Strategy](06_AI_AND_LLM_STRATEGY.md)
- [Operations And Security](07_OPERATIONS_AND_SECURITY.md)
- [Delivery Plan](08_DELIVERY_PLAN.md)
- [Developer Experience](09_DEVELOPER_EXPERIENCE.md)

### Deployment and collector details

- [Agent Multi-Site Configuration](configuration/agent-multi-site.md)
- [Browser Crawler And JavaScript Monitoring](collectors/browser-crawler.md)
- [Dashboard API Surface](dashboard.md)
- [Pantheon WordPress Monitoring](platforms/pantheon-wordpress.md)

### Supporting references

- [Architecture Decisions](decisions)
- [Brand Assets](brand/README.md)
- [Services](../services/README.md)

## Quick start

```powershell
docker compose -f services\compose.yaml up -d postgres18
go run ./cmd/aegrail --help
go run ./cmd/aegrail db migrate
go run ./cmd/aegrail hub serve
go run ./cmd/aegrail agent --help
go run ./cmd/aegrail collector --help
```

## Notes

- `docs/tracker.md`, `idea.md`, and internal draft design sets were removed after consolidation.
- Current dashboard work lives in `dashboard/`, and its backend endpoints are described in `dashboard.md`.
