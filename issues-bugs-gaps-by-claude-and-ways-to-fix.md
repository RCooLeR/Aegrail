# Aegrail — Issues, Bugs & Gaps Analysis

**Analyzed:** 2026-05-18 (fourth full pass — all files read from scratch)
**Scope:** Full codebase — `agent/` and `hub/` modules
**Analysis:** Fresh read of every source file; no assumptions carried from prior passes.

---

## What Was Fixed Since Last Analysis

All 8 issues from the previous report were verified resolved in the current source.

| ID | Summary | Fix Verified In |
|---|---|---|
| BUG-01 | Redis `Allow` non-atomic INCR+EXPIRE | `Allow` now runs a single Lua script: `INCR` + conditional `PEXPIRE` in one Redis round-trip (`hub/internal/adapters/redis/queue.go:145`) |
| BUG-02 | Model-analysis fallback iterated without a limit | Fallback now checks `result.Scopes >= limit \|\| result.Findings >= limit` at each org/project/environment level before entering the next one |
| SEC-01 | `dashboardCSRFSecretFallback` was process-local | `NewHubRouter` panics with an explicit error when `hub.HubUsersConfigured()` is true but `DashboardCSRFSecret` is empty |
| ARCH-01 | `HubUsersExist` cache never invalidated on user deletion | `markHubUsersUnknown()` is called in `DeleteHubUser` when `remaining == 0` |
| ARCH-02 | Model-analysis fallback activated silently | `warnModelAnalysisQueueScopeFallback()` fires once via `sync.Once` and routes the warning through `h.backgroundError` |
| OPS-01 | Invalid CIDR entries were silently ignored at startup | `ValidateServe` returns an error listing every bad entry if `TrustedProxyErrors` is non-empty; invalid entries block startup |
| TEST-01 | No unit tests for model-analysis queue paths | Codex added model-analysis scope and fallback tests |
| TEST-02 | No PostgreSQL integration tests for critical adapters | Codex added opt-in integration tests for session `last_login_at`, bootstrap locking, and stale TOTP activation |

---

## Active Issues

## Codex Follow-Up Fixes

Implemented on 2026-05-18 after this fourth pass:

| ID | Resolution |
|---|---|
| BUG-01 | Added `woocommerce` to the accepted site-kind list and covered validation with an agent config test. |
| ARCH-01 | Added `DELETE /api/v1/access/users/{id}` with admin auth, self-delete protection, `204` on success, and `404` for missing users. |
| ARCH-02 | Added centralized Hub HTTP error mapping so not-found domain/repository errors return `404` while validation errors still return `400`. |
| TEST-01 | Moved the in-memory auth limiter into each router instance and added a regression test proving one router's blocked state does not affect another. |

The issue details below are retained as the source analysis. The table above is the current implementation status.

### Bugs

---

#### BUG-01 — `kind: woocommerce` accepted by normalizer but rejected by validator

**File:** `agent/internal/agent/server_config.go:215` (normalizer), `agent/internal/agent/server_config.go:622` (validator)

`NormalizeServerConfig` explicitly handles `kind: woocommerce` — it assigns the `wordpress` file-watch profile when the site kind is `woocommerce`:

```go
case "wordpress", "wordpress-multisite", "woocommerce":
    site.Files.Profiles = []string{"wordpress"}
```

`ValidateServerConfig` then calls `isKnownSiteKind` which does not include `woocommerce`:

```go
func isKnownSiteKind(kind string) bool {
    switch kind {
    case "wordpress", "wordpress-multisite", "prestashop", "generic-php", "mautic", "yii2-rbac", "laravel":
        return true
    ...
    }
}
```

Any operator who configures `kind: woocommerce` gets a validation error ("kind is unknown") and the agent refuses to start. The normalization code confirms the intent to support WooCommerce as a site variant — the omission from `isKnownSiteKind` is an oversight.

`isKnownWatchProfile` does include `woocommerce` (line 633), further confirming the intent.

**Fix:** Add `"woocommerce"` to the `isKnownSiteKind` switch:

```go
case "wordpress", "wordpress-multisite", "woocommerce", "prestashop", "generic-php", "mautic", "yii2-rbac", "laravel":
    return true
```

---

### Architecture / Design

---

#### ARCH-01 — No HTTP endpoint for user deletion

**File:** `hub/internal/adapters/http/hub_router.go` (router registration), `hub/internal/hub/users.go:203`

The full deletion stack exists:
- `hub.DeleteHubUser` domain method (calls `ports.DeleteHubUserRepository`)
- `postgres.HubUserRepository.DeleteHubUser` — runs in a transaction, deletes the user, counts remaining, returns the count
- `hub.markHubUsersUnknown()` — called when `remaining == 0`

But the router contains no `DELETE /api/v1/access/users/{id}` route. The only user-related `DELETE` endpoint is TOTP disable:

```go
router.Delete("/api/v1/access/users/{id}/totp", ...)
```

As a consequence:
1. Users cannot be deleted through the HTTP API.
2. `markHubUsersUnknown()` can never be called from HTTP traffic — the code path is effectively dead.

**Fix:** Add the route and handler:

```go
router.Delete("/api/v1/access/users/{id}", withHubAuth(hub, options, "admin", deleteHubUserHandler(hub)))
```

With a `deleteHubUserHandler` that calls `hub.DeleteHubUser` and returns 204 on success, 403 if the caller attempts to delete their own account (to prevent lockout), and 404 if the user does not exist.

---

#### ARCH-02 — All domain errors return HTTP 400 in the handler layer

**File:** `hub/internal/adapters/http/hub_router.go:664` (example in `ingestEventsHandler`)

The ingest handler, and the majority of handlers in the router, map every domain error to `http.StatusBadRequest`:

```go
result, err := hub.IngestEvents(r.Context(), input)
if err != nil {
    writeError(w, http.StatusBadRequest, err.Error())
    return
}
```

Domain errors include not-found conditions (`organization %q does not exist`, `host %q does not exist in environment`), which are semantically "404 Not Found", not "400 Bad Request". Returning 400 misleads API clients into thinking their request body is malformed, when the issue is that the referenced resource does not exist.

This is a systematic pattern throughout the router (findings, inventory, model analysis, etc.).

**Fix:** Introduce a typed error for not-found conditions in the domain layer (e.g., `ErrNotFound` or a sentinel type), and map it to 404 at the handler boundary:

```go
if errors.Is(err, hub.ErrNotFound) {
    writeError(w, http.StatusNotFound, err.Error())
    return
}
writeError(w, http.StatusBadRequest, err.Error())
```

At minimum, handle the ingest endpoint first since agents rely on it and need to distinguish "bad payload" (fix the data) from "resource not registered" (fix the agent configuration).

---

### Testing

---

#### TEST-01 — `hubAuthLimiter` is a package-level variable shared across test cases

**File:** `hub/internal/adapters/http/hub_router.go:42`

```go
var hubAuthLimiter = newHubAuthRateLimiter(defaultAuthRateLimit, defaultAuthRateWindow)
```

`hubAuthLimiter` is a package-level singleton. Every call to `NewHubRouter` uses the same limiter. In tests that create multiple routers or that run multiple login attempts across different test cases within the same test binary, the in-memory attempt counters are shared. A test that exhausts the rate limit leaves the limiter in a blocked state for subsequent tests.

This explains any intermittent test failures in auth-path tests when run alongside rate-limit tests.

**Fix:** Move the limiter into `HubOptions` or construct it inside `NewHubRouter`:

```go
func NewHubRouter(meta domain.AppMeta, hub *hubapp.Hub, options HubOptions) http.Handler {
    authLimiter := newHubAuthRateLimiter(defaultAuthRateLimit, defaultAuthRateWindow)
    // pass authLimiter through closures to login/TOTP handlers
    ...
}
```

This gives each router instance an independent limiter and eliminates cross-test state.

---

## Summary Table

| ID | Category | Severity | File | Status |
|---|---|---|---|---|
| BUG-01 | Bug | Medium | `agent/internal/agent/server_config.go:622` | Open |
| ARCH-01 | Architecture | Medium | `hub/internal/adapters/http/hub_router.go` | Open |
| ARCH-02 | Architecture | Low | `hub/internal/adapters/http/hub_router.go:664` | Open |
| TEST-01 | Testing | Low | `hub/internal/adapters/http/hub_router.go:42` | Open |
