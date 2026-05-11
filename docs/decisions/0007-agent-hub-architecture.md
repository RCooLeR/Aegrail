# ADR 0007: Shape Aegrail As Agent Plus Hub

Date: 2026-05-12
Status: accepted

## Context

Aegrail needs to monitor multiple servers, apps, workers, and databases for the same project. A single local timeline is useful, but the larger value comes from correlating events across hosts and services.

## Decision

Design Aegrail as:

```text
Aegrail Agent / DB Collector -> Aegrail Hub -> CLI / Dashboard / Reports
```

The current local CLI remains a first-class workflow, but domain events and storage should be compatible with distributed labels:

- organization
- project
- environment
- app
- service
- host
- agent
- region
- event time
- received time

## Consequences

- Agents must support offline buffering.
- Hub ingest must authenticate agents.
- Timelines must store both event time and received time.
- Deployment markers become part of the risk model.
- Baselines exist per host and per shared app group.
- The data model must not assume that one `site` equals one server.
