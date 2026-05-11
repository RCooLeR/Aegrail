# ADR 0002: Use `aegrail` As The Binary Name

Date: 2026-05-12
Status: accepted

## Context

The original idea document used the working name Aegrail, but the project now has the product name Aegrail and brand assets already exist under `docs/brand`.

## Decision

Use `aegrail` as the binary name from the start.

The command package is:

```text
app/cmd/aegrail
```

## Consequences

- Documentation, CLI help, and future packaging use one name.
- The original `Aegrail-idea.md` remains as historical product context.
- Old `aegrail` command examples should be updated as docs are touched.
