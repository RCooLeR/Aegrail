package postgres

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rcooler/aegrail/hub/internal/domain"
	"github.com/rcooler/aegrail/hub/internal/ports"
)

func TestHubUserRepositoryIntegration(t *testing.T) {
	ctx := context.Background()
	pool, cleanup := newHubUserIntegrationPool(t, ctx)
	defer cleanup()
	repo := NewHubUserRepository(pool)
	now := time.Date(2026, 5, 17, 10, 0, 0, 0, time.UTC)

	user, err := repo.SaveHubUser(ctx, domain.HubUser{
		Email:             "admin@example.test",
		DisplayName:       "Admin",
		AccessLevel:       "owner",
		Status:            "active",
		PasswordHash:      "hash",
		PasswordSetAt:     &now,
		TwoFactorRequired: true,
	})
	if err != nil {
		t.Fatalf("SaveHubUser returned error: %v", err)
	}
	if _, err := repo.SaveHubUserSession(ctx, domain.HubUserSession{
		UserID:     user.ID,
		TokenHash:  "session-token-hash",
		ExpiresAt:  now.Add(time.Hour),
		CreatedAt:  now,
		LastSeenAt: now,
	}); err != nil {
		t.Fatalf("SaveHubUserSession returned error: %v", err)
	}
	reloaded, ok, err := repo.FindHubUserByID(ctx, user.ID)
	if err != nil || !ok {
		t.Fatalf("FindHubUserByID returned ok=%v err=%v", ok, err)
	}
	if reloaded.LastLoginAt == nil || !reloaded.LastLoginAt.Equal(now) {
		t.Fatalf("LastLoginAt=%v, want %v", reloaded.LastLoginAt, now)
	}

	started, err := repo.StartHubUserTOTP(ctx, user.ID, domain.HubUserTOTPStart{
		PendingSecretCiphertext: "pending-secret-v1",
		StartedAt:               now,
	})
	if err != nil {
		t.Fatalf("StartHubUserTOTP returned error: %v", err)
	}
	if started.PendingTOTPSecretCiphertext != "pending-secret-v1" {
		t.Fatalf("pending secret = %q, want pending-secret-v1", started.PendingTOTPSecretCiphertext)
	}
	_, err = repo.ActivateHubUserTOTP(ctx, user.ID, domain.HubUserTOTPActivation{
		ActiveSecretCiphertext:          "pending-secret-v1",
		ExpectedPendingSecretCiphertext: "stale-secret",
		EnrolledAt:                      now.Add(time.Minute),
	})
	if !errors.Is(err, ports.ErrHubTOTPChanged) {
		t.Fatalf("stale ActivateHubUserTOTP err=%v, want ErrHubTOTPChanged", err)
	}
	activated, err := repo.ActivateHubUserTOTP(ctx, user.ID, domain.HubUserTOTPActivation{
		ActiveSecretCiphertext:          "pending-secret-v1",
		ExpectedPendingSecretCiphertext: "pending-secret-v1",
		EnrolledAt:                      now.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("ActivateHubUserTOTP returned error: %v", err)
	}
	if !activated.TwoFactorEnabled || activated.PendingTOTPSecretCiphertext != "" {
		t.Fatalf("activated user = %#v, want enabled 2FA and cleared pending secret", activated)
	}
}

func TestHubUserRepositoryBootstrapLockIntegration(t *testing.T) {
	ctx := context.Background()
	pool, cleanup := newHubUserIntegrationPool(t, ctx)
	defer cleanup()
	repo := NewHubUserRepository(pool)
	now := time.Date(2026, 5, 17, 11, 0, 0, 0, time.UTC)

	var created atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, didCreate, err := repo.CreateBootstrapHubUser(ctx, domain.HubUser{
				Email:             "owner@example.test",
				DisplayName:       "Owner",
				PasswordHash:      "hash",
				PasswordSetAt:     &now,
				TwoFactorRequired: true,
			})
			if err != nil {
				t.Errorf("CreateBootstrapHubUser returned error: %v", err)
				return
			}
			if didCreate {
				created.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	count, err := repo.CountHubUsers(ctx)
	if err != nil {
		t.Fatalf("CountHubUsers returned error: %v", err)
	}
	if count != 1 || created.Load() != 1 {
		t.Fatalf("count=%d created=%d, want exactly one bootstrap owner", count, created.Load())
	}
}

func newHubUserIntegrationPool(t *testing.T, ctx context.Context) (*pgxpool.Pool, func()) {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("AEGRAIL_TEST_POSTGRES_URL"))
	if databaseURL == "" {
		t.Skip("set AEGRAIL_TEST_POSTGRES_URL to run PostgreSQL adapter integration tests")
	}
	adminPool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect admin pool: %v", err)
	}
	schema := "aegrail_user_test_" + randomHexForTest(t, 8)
	schemaIdent := pgx.Identifier{schema}.Sanitize()
	if _, err := adminPool.Exec(ctx, "CREATE SCHEMA "+schemaIdent); err != nil {
		adminPool.Close()
		t.Fatalf("create test schema: %v", err)
	}

	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		_, _ = adminPool.Exec(ctx, "DROP SCHEMA "+schemaIdent+" CASCADE")
		adminPool.Close()
		t.Fatalf("parse postgres url: %v", err)
	}
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		_, _ = adminPool.Exec(ctx, "DROP SCHEMA "+schemaIdent+" CASCADE")
		adminPool.Close()
		t.Fatalf("connect test pool: %v", err)
	}
	if _, err := pool.Exec(ctx, hubUserIntegrationSchemaSQL); err != nil {
		pool.Close()
		_, _ = adminPool.Exec(ctx, "DROP SCHEMA "+schemaIdent+" CASCADE")
		adminPool.Close()
		t.Fatalf("create hub user test schema: %v", err)
	}
	return pool, func() {
		pool.Close()
		_, _ = adminPool.Exec(context.Background(), "DROP SCHEMA "+schemaIdent+" CASCADE")
		adminPool.Close()
	}
}

func randomHexForTest(t *testing.T, bytesLen int) string {
	t.Helper()
	buf := make([]byte, bytesLen)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("read random bytes: %v", err)
	}
	return hex.EncodeToString(buf)
}

const hubUserIntegrationSchemaSQL = `
CREATE SEQUENCE hub_user_test_ids;

CREATE TABLE hub_users (
	id uuid PRIMARY KEY DEFAULT (lpad(to_hex(nextval('hub_user_test_ids')), 32, '0'))::uuid,
	email text NOT NULL,
	display_name text NOT NULL DEFAULT '',
	access_level text NOT NULL DEFAULT 'viewer',
	status text NOT NULL DEFAULT 'active',
	password_hash text NOT NULL DEFAULT '',
	password_set_at timestamptz,
	two_factor_required boolean NOT NULL DEFAULT true,
	two_factor_enabled boolean NOT NULL DEFAULT false,
	totp_secret_ciphertext text NOT NULL DEFAULT '',
	totp_enrolled_at timestamptz,
	pending_totp_secret_ciphertext text NOT NULL DEFAULT '',
	pending_totp_started_at timestamptz,
	last_login_at timestamptz,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX hub_users_email_lower_idx ON hub_users (lower(email));

CREATE TABLE hub_user_sessions (
	id uuid PRIMARY KEY DEFAULT (lpad(to_hex(nextval('hub_user_test_ids')), 32, '0'))::uuid,
	user_id uuid NOT NULL REFERENCES hub_users(id) ON DELETE CASCADE,
	token_hash text NOT NULL,
	expires_at timestamptz NOT NULL,
	revoked_at timestamptz,
	created_at timestamptz NOT NULL DEFAULT now(),
	last_seen_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX hub_user_sessions_token_hash_idx ON hub_user_sessions (token_hash);
`
