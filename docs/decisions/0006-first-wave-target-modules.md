# ADR 0006: Prioritize WordPress And PrestaShop Modules

Date: 2026-05-12
Status: accepted

## Context

Aegrail needs to be strong for the first practical targets, not merely generic across PHP applications. The first high-value users are likely maintaining WordPress/WooCommerce and PrestaShop sites, where security signals are concrete and business impact can be high.

## Decision

Treat WordPress/WooCommerce and PrestaShop as first-wave modules.

Secondary PHP targets are Mautic, Yii2, and Laravel. They should reuse the same module, snapshot, diff, and rule infrastructure after the first-wave modules are reliable.

## Consequences

- WordPress and PrestaShop receive dedicated snapshot models and rule packs early.
- Generic PHP heuristics remain useful but do not replace CMS-specific detection.
- Mautic, Yii2, and Laravel can share framework-level helpers later without weakening first-wave coverage.
