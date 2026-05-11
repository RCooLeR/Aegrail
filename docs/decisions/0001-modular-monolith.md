# ADR 0001: Start With A Modular Monolith

Date: 2026-05-12
Status: accepted

## Context

Aegrail needs a reliable security analysis core, a CLI, future HTTP API, PostgreSQL storage, source-specific modules, and optional local LLM integration through Ollama. The system will handle sensitive evidence, so operational simplicity and clear data boundaries matter more than early service decomposition.

## Decision

Build the first implementation as a modular monolith in Go using ports-and-adapters boundaries.

The CLI, future HTTP server, background jobs, and tests will all call the same runtime use-case packages. Source-specific logic, such as PrestaShop and WordPress support, will live in modules that register collectors, normalizers, snapshot builders, and rules.

## Consequences

Positive:

- Simple local deployment.
- Easier debugging during MVP.
- No distributed tracing, network retries, or cross-service auth for the first release.
- Clear package boundaries still allow workers or services later.
- CLI and HTTP behavior stay consistent because they share use cases.

Tradeoffs:

- The main binary can grow if package boundaries are not enforced.
- Long-running imports and analysis jobs need careful orchestration inside one codebase.
- Future service extraction requires discipline around ports and data contracts.

## Guardrails

- Domain packages must not import adapters.
- CLI and HTTP handlers must not contain business logic.
- Ollama must stay behind an interface.
- PostgreSQL repository code must stay in the PostgreSQL adapter.
- PrestaShop and WordPress-specific logic must stay in their modules unless it is truly generic.
