# Aegrail — Issues, Bugs & Gaps Analysis

**Analyzed:** 2026-05-18 (sixth full pass — all files read from scratch)
**Scope:** Full codebase — `agent/` and `hub/` modules
**Analysis:** Fresh read of every source file; no assumptions carried from prior passes.

---

## What Was Fixed Since Last Analysis

All 4 issues from the fifth pass were verified resolved in the current source.

| ID | Summary | Fix Verified In |
|---|---|---|
| BUG-01 | `kind: woocommerce` accepted by normalizer but rejected by validator | `isKnownSiteKind` now includes `"woocommerce"` (`agent/internal/agent/server_config.go:624`) |
| ARCH-01 | No HTTP endpoint for user deletion | `DELETE /api/v1/access/users/{id}` route added at line 136; `deleteHubUserHandler` at line 1679 with self-delete protection, 204 on success, 404 for missing users |
| ARCH-02 | All domain errors returned HTTP 400 | `writeHubError` + `hubErrorStatus` added; all handlers converted from `writeError(w, http.StatusBadRequest, err.Error())` to `writeHubError(w, err)` |
| TEST-01 | `hubAuthLimiter` was a package-level singleton shared across tests | `authRateLimiter` moved to unexported field in `HubOptions`; initialized per-router in `NewHubRouter`; `TestHubAuthRateLimiterIsScopedPerRouter` regression test added |

---

## Active Issues

## Codex Follow-Up Fixes

Implemented on 2026-05-18 after this sixth pass:

| ID | Resolution |
|---|---|
| BUG-01 | Added last-active-owner protection in the Hub domain layer and repeated it inside PostgreSQL update/delete transactions under an advisory lock. |
| BUG-02 | Mapped missing PostgreSQL findings/users/model reports to `ErrHubNotFound` instead of leaking raw `pgx.ErrNoRows` to the HTTP layer. |
| ARCH-01 | Removed the `no rows in result set` HTTP string match; not-found handling now relies on typed/sentinel errors. |
| ARCH-02 | Removed the unreachable trusted-proxy warning loop after `ValidateServe()`. |
| TEST-01 | Added HTTP and PostgreSQL integration coverage for last-owner downgrade/delete protection. |

Security audit follow-up implemented on 2026-05-18:

| ID | Resolution |
|---|---|
| SEC-01 | Wrapped model-analysis issue context and evidence JSON in explicit untrusted-data delimiters, added a prompt rule not to treat evidence as instructions, and bounded issue context title/summary/id fields. |
| SEC-02 | Prevented silent agent wire public key replacement. Re-provisioning an existing agent id with a different node key now returns `409`; PostgreSQL enforces the same rule in the upsert. |
| SEC-03 | Removed the `Host`-header fallback from loopback detection; unparseable remote addresses now fail closed. |

User-security follow-up implemented on 2026-05-18:

| ID | Resolution |
|---|---|
| BUG-01 | Made Hub user creation insert-only by normalized email. Duplicate create calls now return `409` and cannot overwrite owner access, status, password hash, or 2FA requirement. |
| ARCH-01 | Replaced bare SHA-256 TOTP secret key derivation with HKDF-SHA-256-backed `v2` ciphertext. No legacy decrypt fallback is kept because the project is not deployed yet. |
| TEST-01 | Added HTTP duplicate-create regression coverage for owner and non-owner users plus PostgreSQL duplicate insert coverage. |

The issue details below are retained as the source analysis. The table above is the current implementation status.

### Bugs

---

#### BUG-01 — `DeleteHubUser` and `UpdateHubUser` have no last-owner protection

**Files:** `hub/internal/hub/users.go:203` (`DeleteHubUser`), `hub/internal/hub/users.go:179` (`UpdateHubUser`), `hub/internal/adapters/http/hub_router.go:1679` (`deleteHubUserHandler`)

An `admin`-level user can:
1. `DELETE /api/v1/access/users/{owner-id}` — the only guard is self-delete prevention. If the caller is an admin targeting the only owner, the deletion succeeds and the system is left with no owner.
2. `PATCH /api/v1/access/users/{owner-id}` — there is no check preventing an admin from downgrading the last owner to `admin`, `operator`, or `viewer`.
3. `PATCH /api/v1/access/users/{owner-id}` with `"status": "disabled"` — disabling the last active owner account locks out all owner-level operations.

The domain layer (`hub/internal/hub/users.go`) performs no owner-count check before either operation. The result: an admin (or a single owner who grants another user admin before being deleted) can permanently remove all `owner` access. Recovery requires direct database access.

This is an access-control gap, not just an ergonomics issue — a rogue or careless admin can irreversibly degrade the system's administrative capabilities.

**Fix:**

In `hub/internal/hub/users.go`, before calling `deleteRepo.DeleteHubUser`:

```go
// Count remaining owners before deleting.
// Requires a CountOwnersByAccessLevel helper or listing all users.
existing, ok, err := h.users.FindHubUserByID(ctx, userID)
if err != nil { return err }
if !ok { return ErrHubNotFound }
if existing.AccessLevel == "owner" {
    owners, err := h.countHubOwners(ctx)
    if err != nil { return err }
    if owners <= 1 {
        return errors.New("cannot delete the last owner account")
    }
}
```

Similarly, before calling `h.users.UpdateHubUser`, when the existing access level is `"owner"` and the new access level is not `"owner"`:

```go
owners, err := h.countHubOwners(ctx)
if err != nil { return domain.HubUser{}, err }
if owners <= 1 {
    return domain.HubUser{}, errors.New("cannot remove owner access from the last owner account")
}
```

`countHubOwners` can be implemented with a filtered `CountHubUsers` or by listing users and counting access levels. The postgres adapter already has an efficient `COUNT(*)` path; adding `WHERE access_level = 'owner'` is the minimal addition.

---

#### BUG-02 — `postgres.GetHubFinding`, `UpdateHubFindingStatus`, and `UpdateHubUser` don't wrap `pgx.ErrNoRows` as `ErrHubNotFound`

**Files:**
- `hub/internal/adapters/postgres/findings.go:272` (`GetHubFinding`)
- `hub/internal/adapters/postgres/findings.go:367` (`UpdateHubFindingStatus`)
- `hub/internal/adapters/postgres/users.go:170` (`UpdateHubUser`)

All three functions perform an `UPDATE ... RETURNING` or a plain `SELECT` query and return the raw pgx error when no row matches. The `pgx.ErrNoRows` is not wrapped as `ports.ErrHubNotFound`. As a result, the `errors.Is(err, hubapp.ErrHubNotFound)` check in `hubErrorStatus` misses these cases, and the fallback string-match on `"no rows in result set"` (a pgx implementation detail) is what makes 404 responses work.

```go
// GetHubFinding — no ErrNoRows check:
if err := r.pool.QueryRow(ctx, query, ...).Scan(...); err != nil {
    return domain.HubFinding{}, err  // returns pgx.ErrNoRows directly
}

// UpdateHubUser — same pattern:
return scanHubUser(r.pool.QueryRow(ctx, query, ...))  // pgx.ErrNoRows on miss
```

This is inconsistent with `DeleteHubUser` which correctly returns `ports.ErrHubNotFound` when `RowsAffected() == 0` (line 193).

**Fix:** Add `pgx.ErrNoRows` checks in all three functions:

```go
// GetHubFinding
if err != nil {
    if errors.Is(err, pgx.ErrNoRows) {
        return domain.HubFinding{}, ports.ErrHubNotFound
    }
    return domain.HubFinding{}, err
}

// UpdateHubFindingStatus
if err != nil {
    if errors.Is(err, pgx.ErrNoRows) {
        return domain.HubFinding{}, ports.ErrHubNotFound
    }
    return domain.HubFinding{}, err
}

// UpdateHubUser
user, err := scanHubUser(r.pool.QueryRow(ctx, query, ...))
if errors.Is(err, pgx.ErrNoRows) {
    return domain.HubUser{}, ports.ErrHubNotFound
}
return user, err
```

---

### Architecture / Design

---

#### ARCH-01 — `hubErrorStatus` string-matching fallback is fragile

**File:** `hub/internal/adapters/http/hub_router.go:3219`

```go
func hubErrorStatus(err error) int {
    if errors.Is(err, hubapp.ErrHubNotFound) {
        return http.StatusNotFound
    }
    message := strings.ToLower(err.Error())
    if strings.Contains(message, " does not exist") ||
        strings.Contains(message, " was not found") ||
        strings.Contains(message, " not found") ||
        strings.Contains(message, "no rows in result set") {  // pgx implementation detail
        return http.StatusNotFound
    }
    return http.StatusBadRequest
}
```

The `"no rows in result set"` match is a pgx-specific error string. If pgx changes its error message format (e.g., in a major version upgrade), these checks would silently regress — not-found conditions would start returning `400 Bad Request` instead of `404 Not Found`.

This fallback is load-bearing today because `GetHubFinding`, `UpdateHubFindingStatus`, and `UpdateHubUser` don't return `ErrHubNotFound` (BUG-02 above). Once BUG-02 is fixed, the string-match fallback becomes a belt-and-suspenders measure and the pgx-specific match can be removed.

**Fix:** After fixing BUG-02, remove the `"no rows in result set"` clause. The remaining domain-message checks (`" does not exist"`, `" not found"`, `" was not found"`) can be retained as a belt-and-suspenders for domain-layer errors that compose their own messages without wrapping `ErrHubNotFound`.

---

#### ARCH-02 — Dead code: TrustedProxy error log after `ValidateServe`

**File:** `hub/internal/adapters/cli/cli.go:135`

```go
if err := container.Config.ValidateServe(); err != nil {
    return err
}
for _, parseError := range container.Config.Hub.TrustedProxyErrors {
    container.Logger.Warn().Str("cidr", parseError).Msg("ignored invalid trusted proxy CIDR")
}
```

`ValidateServe()` returns an error (`fmt.Errorf("AEGRAIL_TRUSTED_PROXY_CIDRS contains invalid entries: ...")`) when `TrustedProxyErrors` is non-empty. The `for` loop immediately after is therefore unreachable:
- If `TrustedProxyErrors` is non-empty → `ValidateServe()` returns an error, the function returns before the loop
- If `TrustedProxyErrors` is empty → the loop body never executes

The loop was likely written before `ValidateServe()` was made to block on CIDR parse errors, and was meant to warn about silently-ignored entries. Now both behaviors coexist but only the error-blocking path ever runs.

**Fix:** Remove lines 135–137 (the unreachable `for` loop).

---

### Testing

---

#### TEST-01 — No test for last-owner deletion/downgrade protection

**File:** `hub/internal/adapters/http/hub_users_router_test.go`

The existing `TestHubRouterManagesUsersAndTOTPEnrollment` test covers:
- Self-delete returns 403
- Missing user returns 404
- Deleting a non-owner second user returns 204

It does not cover:
- Admin deleting the last owner returns 403/400
- Admin downgrading the last owner to non-owner returns 403/400

Once BUG-01 is fixed, these cases should be added to prevent regression.

---

## Summary Table

| ID | Category | Severity | File | Status |
|---|---|---|---|---|
| BUG-01 | Bug | High | `hub/internal/hub/users.go:203,179` | Open |
| BUG-02 | Bug | Low | `hub/internal/adapters/postgres/findings.go:272,367` / `users.go:170` | Open |
| ARCH-01 | Architecture | Low | `hub/internal/adapters/http/hub_router.go:3219` | Open (depends on BUG-02) |
| ARCH-02 | Architecture | Low | `hub/internal/adapters/cli/cli.go:135` | Open |
| TEST-01 | Testing | Low | `hub/internal/adapters/http/hub_users_router_test.go` | Open (depends on BUG-01) |
