# Aegrail — Issues, Bugs & Gaps Analysis

**Analyzed:** 2026-05-17  
**Scope:** Full codebase — `agent/` and `hub/` modules  
**Analysis:** Fresh read of all source files; no assumptions carried from prior versions.

## Codex Resolution Pass

Applied in the current worktree after this report:

- BUG-02: inline auto-correlation now reports errors through the Hub background error hook.
- BUG-03: file and log scanners now fall back safely when `filepath.Abs` fails.
- BUG-04: TOTP activation is conditional on the pending secret that was verified.
- SEC-01: the process-local auth limiter now sweeps stale keys.
- SEC-02: dashboard CSRF tokens are derived from a Hub-side secret.
- SEC-03: PostgreSQL bootstrap user creation uses an advisory transaction lock.
- SEC-04: Redis-backed shared auth rate limiting is used when Redis is configured.
- ARCH-01: authenticated requests stop calling `CountHubUsers` after users exist.
- ARCH-02: topology reads use a direct environment-scope query path.
- ARCH-03: model-analysis queue selection can query scopes with unanalyzed open findings directly.
- ARCH-04: Agent atomic file writing now lives in shared `agent/internal/fsutil`.
- OPS-01: Hub `serve` now requires an explicit `AEGRAIL_DATABASE_URL`.
- OPS-02: trusted proxy CIDRs are parsed at startup and invalid entries are warned.
- TEST-01/02: added focused HTTP auth/CSRF/rate-limit and wire tamper/expiry/node mismatch tests.

Notes:

- BUG-01 was already fixed before this pass: `SaveHubUserSession` persists `last_login_at`.
- TEST-03 was already covered by existing correlation tests in `hub/internal/hub/*correlation*_test.go`.

---

## What Was Fixed Since Last Analysis

The following issues identified in the previous report were resolved and are **not listed again** in the active issues below:

| Previously | Fix Applied |
|---|---|
| Non-atomic state-file writes (crash = corruption) | `writeFileAtomicSync` added to `agent/internal/agent/` and `agent/internal/collector/` — temp-file + fsync + rename pattern used everywhere |
| Queue batch file missing `file.Sync()` | Same fix — `EnqueueEvents` and `Install` now use `writeFileAtomicSync` |
| HTTP server missing ReadTimeout / WriteTimeout / IdleTimeout | All four timeouts now set: `ReadHeaderTimeout: 5s`, `ReadTimeout: 15s`, `WriteTimeout: 60s`, `IdleTimeout: 60s` |
| DB connection pool unconfigured | `MinConns: 1`, `MaxConns: 20`, `MaxConnLifetime: 1h`, `MaxConnIdleTime: 10m`, `HealthCheckPeriod: 1m` now set in `pool.go` |
| `TwoFactorRequired` hardcoded `true` in `CreateHubUser` / `UpdateHubUser` | Now reads `input.TwoFactorRequired` correctly in both methods |
| TOTP replay attack — used codes never invalidated | `consumeTOTPCode` stores used `(userID, counter)` pairs for 90 s in `h.totpReplay`; test added in `auth_test.go` |
| No graceful shutdown for background workers | `WaitForWorkers()` called during server shutdown with a 5-second timeout |
| Dead code `region = ""` in ingest.go | Removed — `buildIngestEvent` is clean |
| `listInventoryScopesHandler` N+1 nested DB queries | Replaced with single `hub.ListInventoryScopeTree(ctx)` call |
| Redis client leaked when `webhook.NewNotificationSink` fails | `c.redis.Close()` now called in the error path in `container.go` |
| No rate limiting on `/api/v1/auth/login` | `hubAuthLimiter` (10 attempts/min per IP+email) now applied to login and TOTP endpoints |
| `parseQueryLimit` had no upper-bound enforcement | `maxHTTPQueryLimit = 5000` cap enforced |

---

## Active Issues

### Bugs

---

#### BUG-01 — `LastLoginAt` is set in memory but never persisted to the database

**File:** `hub/internal/hub/auth.go:117`

```go
user.LastLoginAt = &now
return LoginHubUserResult{User: user, ...}  // DB record is never updated
```

`LoginHubUser` assigns the current time to `user.LastLoginAt` but does not call any repository method to save it. The value is visible in the JSON response of the login endpoint but does not survive the request.

**Fix:** Add an `UpdateHubUserLastLoginAt(ctx, userID, now)` method to the user repository and call it from `LoginHubUser` before returning.

---

#### BUG-02 — `autoCorrelateIngestEvents` silently discards errors

**File:** `hub/internal/hub/ingest.go:203`

```go
_, _ = h.CorrelateEvents(ctx, CorrelateEventsInput{...})
```

When Redis is unavailable and the async queue fallback is triggered, correlation errors are swallowed entirely. Database errors, missing finding repositories, and inventory resolution failures are all invisible.

**Fix:** Accept an `onError func(error)` callback (already on the worker options) or at minimum log the error through the Hub's logger so operators can see when synchronous correlation is failing.

---

#### BUG-03 — `filepath.Abs` error silently ignored in `scanPaths`

**File:** `agent/internal/agent/watch.go:429`

```go
queueAbs, _ := filepath.Abs(queueDir)
```

If `filepath.Abs` fails (process cannot determine its working directory), `queueAbs` is `""`. The subsequent `shouldSkipDir(current, queueAbs)` check will then never match the queue directory, allowing queue files to be hashed and reported as file-change events.

**Fix:** Return the error or fall back to the raw `queueDir` string:

```go
queueAbs, err := filepath.Abs(queueDir)
if err != nil {
    queueAbs = queueDir
}
```

---

#### BUG-04 — TOCTOU race in `VerifyHubUserTOTP` between reading and activating

**File:** `hub/internal/hub/users.go:189-213`

The function reads the user, checks `PendingTOTPSecretCiphertext`, verifies the TOTP code, then calls `ActivateHubUserTOTP`. Under concurrent requests (e.g., a user double-submitting the enrollment form), two goroutines can verify the same pending code and both proceed to activate — potentially storing two different secrets if the second request raced a new `StartHubUserTOTP` in between.

**Fix:** Make `ActivateHubUserTOTP` check that the `PendingTOTPSecretCiphertext` being activated matches the value that was read, using a conditional UPDATE (`WHERE pending_secret = $old_value`). Return an error if the conditional update matches zero rows.

---

### Security

---

#### SEC-01 — In-memory auth rate limiter grows without bound

**File:** `hub/internal/adapters/http/hub_router.go:2386`

```go
type hubAuthRateLimiter struct {
    attempts map[string][]time.Time
}
```

Each `allow()` call prunes entries for the specific key being checked, but keys for IP+email combinations that are never seen again remain in the map indefinitely. An attacker cycling through many unique source IPs (or email addresses) can grow this map without limit, leading to a memory exhaustion DoS.

**Fix:** Add a periodic sweeper goroutine (or use a TTL-based map / LRU cache) that removes keys whose last attempt is older than the rate-limit window. Alternatively, use an existing library like `golang.org/x/time/rate` per-key with LRU eviction.

---

#### SEC-02 — CSRF token is derivable from the session cookie

**File:** `hub/internal/adapters/http/hub_router.go:2890-2898`

```go
func dashboardCSRFToken(sessionToken string) string {
    mac := hmac.New(sha256.New, []byte(sessionToken))
    mac.Write([]byte(dashboardProtocol))
    return hex.EncodeToString(mac.Sum(nil))
}
```

The CSRF token is an HMAC of the session token keyed by the session token itself. Any code that can read the session cookie can compute a valid CSRF token. The protection depends entirely on `SameSite=Strict` preventing cross-site cookie access. In environments where `SameSite` is not enforced (older browsers, non-browser clients, subdomain attacks), CSRF protection degrades to nothing.

**Fix:** Derive the CSRF token from a server-side secret (e.g., `HMAC(server_secret, session_token)`) rather than from the session token itself. This way an attacker who steals the session cookie cannot compute the CSRF token without also knowing the server secret.

---

#### SEC-03 — Bootstrap mutex is process-local; multi-instance deployments have a TOCTOU race

**File:** `hub/internal/adapters/http/hub_router.go:1580-1598`

```go
hubBootstrapUserMu.Lock()
count, err := hub.CountHubUsers(r.Context())
// ...
bootstrap = count == 0
```

`hubBootstrapUserMu` is a `sync.Mutex` — it only synchronizes within a single process. When two Hub instances are running simultaneously and both receive the first-user-creation request, both see `count == 0` and both attempt to create the owner user. The result is two owner accounts instead of one.

**Fix:** Use a database-level advisory lock (e.g., `pg_try_advisory_lock`) held for the duration of the bootstrap creation transaction, or use a unique constraint on `access_level = 'owner'` combined with `INSERT ... ON CONFLICT DO NOTHING` + count check.

---

#### SEC-04 — Auth rate limiter state is not shared across Hub instances

**File:** `hub/internal/adapters/http/hub_router.go:42`

```go
var hubAuthLimiter = newHubAuthRateLimiter(10, time.Minute)
```

Like `hubBootstrapUserMu`, `hubAuthLimiter` is process-local. An attacker can multiply their attempt budget by the number of Hub instances behind the load balancer.

**Fix:** Back the rate limiter with Redis (increment + expire pattern) when Redis is configured, and fall back to process-local limiting when it is not.

---

### Architecture / Design

---

#### ARCH-01 — `requireHubUser` queries `CountHubUsers` on every authenticated request

**File:** `hub/internal/adapters/http/hub_router.go:2813`

```go
count, err := hub.CountHubUsers(r.Context())
```

Every API call that goes through `requireHubUser` (which is every authenticated endpoint) issues a `COUNT(*)` to the database to check whether any users are configured. This adds one extra round-trip per request.

**Fix:** Cache the "users configured" boolean in the `Hub` struct and set it when the user repository is attached (or on first login). Invalidate only when a user is created or deleted. Alternatively, move the bootstrap check to startup and express "configured" as a boolean flag set once.

---

#### ARCH-02 — `listInventoryTopologyHandler` loads the entire scope tree to filter one environment

**File:** `hub/internal/adapters/http/hub_router.go:2235-2285`

`ListInventoryScopeTree` fetches all organizations, projects, environments, apps, services, hosts, and agents. The handler then iterates the full tree to find the single matching `org/project/environment`. In a multi-tenant deployment this is an expensive full-table scan for every topology request.

**Fix:** Add a `GetInventoryScopeForEnvironment(ctx, org, project, env)` method to the Hub and inventory repository that queries directly by slug path, and use it from this handler.

---

#### ARCH-03 — `AnalyzeModelAnalysisQueue` iterates all organizations and environments

**File:** `hub/internal/hub/model_analysis_queue.go:136-156`

The model analysis worker calls `ListOrganizations`, then for each org calls `ListProjects`, then for each project calls `ListEnvironments`. At scale this is O(orgs × projects × environments) round-trips per worker tick.

**Fix:** Add a `ListEnvironmentsNeedingModelAnalysis(ctx, limit)` query to the repository that returns the relevant environments directly (e.g., environments that have open findings without a model analysis report), avoiding nested iteration.

---

#### ARCH-04 — `writeFileAtomicSync` is duplicated across two packages

**Files:** `agent/internal/agent/atomic_write.go`, `agent/internal/collector/atomic_write.go`

Both files contain byte-for-byte identical implementations. If one is fixed, the other is likely forgotten.

**Fix:** Move `writeFileAtomicSync` and `syncParentDir` to a shared internal package (e.g., `agent/internal/fsutil`) and import it from both packages.

---

### Operations / Configuration

---

#### OPS-01 — Default database URL contains hardcoded credentials and `sslmode=disable`

**File:** `hub/internal/bootstrap/config.go:79`

```go
URL: envString("AEGRAIL_DATABASE_URL", "postgres://aegrail:aegrail@localhost:55432/aegrail?sslmode=disable"),
```

If `AEGRAIL_DATABASE_URL` is not set in a production environment, the server silently connects with these defaults — no TLS and well-known credentials.

**Fix:** Change the default to `""` (empty) and fail fast at startup if the URL is not provided. The `ValidateServe()` function already validates other required secrets; add the database URL there:

```go
if strings.TrimSpace(c.Database.URL) == "" {
    return errors.New("AEGRAIL_DATABASE_URL is required")
}
```

---

#### OPS-02 — Trusted proxy CIDR list is parsed only once via `sync.Once`

**File:** `hub/internal/adapters/http/hub_router.go:3099`

```go
trustedProxyOnce.Do(func() {
    // parse AEGRAIL_TRUSTED_PROXY_CIDRS once
})
```

The trusted proxy CIDRs are read from the environment variable at first HTTP request. Subsequent changes to the env var (e.g., in containerized restarts without a full process restart) are not picked up. More importantly, invalid CIDR entries are silently skipped with no log or error.

**Fix:** Parse `AEGRAIL_TRUSTED_PROXY_CIDRS` at startup in `LoadConfig` and store it in the `Config` struct. Pass it into `HubOptions`. Log a warning for each entry that fails to parse.

---

### Testing

---

#### TEST-01 — No tests for HTTP handler behavior (status codes, error paths, auth enforcement)

The only test file under `hub/` is `auth_test.go`, which covers TOTP replay. There are no tests verifying that:

- Unauthenticated requests to protected endpoints return 401, not 200 or 500.
- CSRF verification rejects requests missing the header.
- `createHubUserHandler` correctly enforces bootstrap logic.
- Error responses from domain layer use the correct HTTP status codes.
- `parseQueryLimit` clamps values correctly.

**Fix:** Add HTTP-level integration tests using `httptest.NewRecorder` and a test-scoped Hub instance. At minimum, cover the auth middleware, login, logout, and the bootstrap flow.

---

#### TEST-02 — No tests for the agent wire protocol (encrypt → send → decrypt round-trip)

`agent/internal/wire/wire.go` and `hub/internal/wire/wire.go` implement the X25519 + AES-256-GCM protocol, but there are no tests verifying that agent-signed envelopes are accepted by the hub decryption path, that expired envelopes are rejected, or that tampered ciphertext is rejected.

**Fix:** Add table-driven tests in a `wire_test.go` file covering: valid envelope, expired timestamp, wrong nonce, bit-flipped ciphertext, mismatched node ID.

---

#### TEST-03 — Correlation engine rules have no unit tests

`hub/internal/hub/correlation.go` contains a set of pattern-matching rules (`isSuspiciousWebEvent`, `isHighSignalFileEvent`, `isDatabaseSecurityEvent`, `isPersistenceEvent`). These rules are purely functional and easy to unit-test, but have no tests.

**Fix:** Add a `correlation_test.go` with table-driven tests for each rule function using representative `domain.TimelineEvent` fixtures, and for `correlateTimelineEvents` with end-to-end chain examples.

---

## Summary Table

| ID | Category | Severity | File | Status |
|---|---|---|---|---|
| BUG-01 | Bug | Medium | `hub/internal/hub/auth.go:117` | Open |
| BUG-02 | Bug | Low | `hub/internal/hub/ingest.go:203` | Open |
| BUG-03 | Bug | Low | `agent/internal/agent/watch.go:429` | Open |
| BUG-04 | Bug | Low | `hub/internal/hub/users.go:203` | Open |
| SEC-01 | Security | High | `hub/internal/adapters/http/hub_router.go:2386` | Open |
| SEC-02 | Security | Medium | `hub/internal/adapters/http/hub_router.go:2890` | Open |
| SEC-03 | Security | High | `hub/internal/adapters/http/hub_router.go:1580` | Open |
| SEC-04 | Security | Medium | `hub/internal/adapters/http/hub_router.go:42` | Open |
| ARCH-01 | Architecture | Medium | `hub/internal/adapters/http/hub_router.go:2813` | Open |
| ARCH-02 | Architecture | Low | `hub/internal/adapters/http/hub_router.go:2235` | Open |
| ARCH-03 | Architecture | Low | `hub/internal/hub/model_analysis_queue.go:136` | Open |
| ARCH-04 | Architecture | Low | `agent/internal/agent/atomic_write.go` | Open |
| OPS-01 | Operations | High | `hub/internal/bootstrap/config.go:79` | Open |
| OPS-02 | Operations | Low | `hub/internal/adapters/http/hub_router.go:3099` | Open |
| TEST-01 | Testing | Medium | `hub/internal/adapters/http/` | Open |
| TEST-02 | Testing | Medium | `agent/internal/wire/`, `hub/internal/wire/` | Open |
| TEST-03 | Testing | Low | `hub/internal/hub/correlation.go` | Open |
