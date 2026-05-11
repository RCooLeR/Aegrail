# ADR 0005: Copy Imported Evidence Into A Local Archive

Date: 2026-05-12
Status: accepted

## Context

Aegrail reports need to remain reproducible after the original log or snapshot path disappears. The database should not store large raw evidence blobs in hot tables, but it must keep stable references and hashes.

## Decision

Copy imported local evidence into:

```text
data/evidence/{site_slug}/{import_id}/
```

Store evidence object metadata in PostgreSQL:

- archived URI
- original URI
- relative path
- SHA-256 hash
- content type
- size

Calculate a deterministic source fingerprint from relative paths, sizes, and SHA-256 hashes. Reuse completed imports only when the archived refs still exist.

## Consequences

- Reports can refer back to stable local evidence paths.
- Re-importing the same source is idempotent.
- If archived files are missing but the original source path is still available, Aegrail can repair the archive.
- Raw evidence stays outside hot PostgreSQL tables and remains ignored by Git.
