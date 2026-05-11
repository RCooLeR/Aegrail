# 0008: One Repo, Multiple Runtime Apps

Status: accepted
Date: 2026-05-12

## Context

Aegrail needs to support local investigations and distributed monitoring. The distributed shape has several clear runtime responsibilities: Hub, Agent, database/app Collector, and operator CLI.

Splitting into multiple repositories or services now would add release, versioning, and deployment friction before the core model is stable. Keeping everything in one unstructured application package would make Hub ingest, Agent queueing, and WordPress/PrestaShop collectors harder to maintain.

## Decision

Keep one repository and one Go module for now, but structure the code as multiple internal runtime apps:

- `internal/local`: local/manual investigation workflows
- `internal/hub`: central inventory, ingest, timelines, findings, and reports
- `internal/agent`: per-server watching, queueing, identity, and sending
- `internal/collector`: database and application collectors

Shared contracts remain in `internal/domain` and `internal/ports`. External integrations stay in `internal/adapters`.

The first binary remains `aegrail`, with app-oriented command groups such as:

```text
aegrail hub ...
aegrail agent ...
aegrail collector ...
```

Separate binaries can be added later from the same packages if deployment needs justify it.

## Consequences

- The codebase can grow like several apps without early microservice overhead.
- Hub, Agent, and Collector work can evolve independently inside the same repo.
- Shared domain and protocol types stay version-aligned.
- Bootstrap wiring must stay disciplined so runtime-specific dependencies do not leak across apps.
