# Aegrail Docs

Aegrail is an evidence-first monitoring and incident triage platform for WordPress, PrestaShop, and PHP application estates.

## Canonical Documents

- [Product Vision](01_PRODUCT_VISION.md)
- [Architecture](02_ARCHITECTURE.md)
- [Domain Model](03_DOMAIN_MODEL.md)
- [Evidence Collection](04_EVIDENCE_COLLECTION.md)
- [Detection And Correlation](05_DETECTION_AND_CORRELATION.md)
- [AI And LLM Strategy](06_AI_AND_LLM_STRATEGY.md)
- [Operations And Security](07_OPERATIONS_AND_SECURITY.md)
- [Delivery Plan](08_DELIVERY_PLAN.md)
- [Developer Experience](09_DEVELOPER_EXPERIENCE.md)

## Supporting Specs

- [Agent Multi-Site Configuration](configuration/agent-multi-site.md)
- [Browser Crawler And JavaScript Monitoring](collectors/browser-crawler.md)
- [Pantheon WordPress Monitoring](platforms/pantheon-wordpress.md)
- [Tracker](tracker.md)
- [Architecture Decisions](decisions)
- [Brand Assets](brand/README.md)
- [Services](../services/README.md)

## Documentation Principles

- Keep product intent in `01_PRODUCT_VISION.md`.
- Keep durable module boundaries in `02_ARCHITECTURE.md`.
- Keep entities and relationships in `03_DOMAIN_MODEL.md`.
- Keep collectors, agents, queues, and source behavior in `04_EVIDENCE_COLLECTION.md`.
- Keep rules, findings, baselines, and dashboard triage in `05_DETECTION_AND_CORRELATION.md`.
- Keep model behavior and prompt contracts in `06_AI_AND_LLM_STRATEGY.md`.
- Keep deployment, secrets, auth, backups, and failure modes in `07_OPERATIONS_AND_SECURITY.md`.
- Keep phases and MVP guardrails in `08_DELIVERY_PLAN.md`.
- Keep local commands, testing, and repo conventions in `09_DEVELOPER_EXPERIENCE.md`.
- Use supporting specs only for deeper topic detail.
