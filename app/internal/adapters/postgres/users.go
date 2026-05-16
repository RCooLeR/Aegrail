package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rcooler/aegrail/internal/domain"
)

type HubUserRepository struct {
	pool *pgxpool.Pool
}

func NewHubUserRepository(pool *pgxpool.Pool) *HubUserRepository {
	return &HubUserRepository{pool: pool}
}

func (r *HubUserRepository) SaveHubUser(ctx context.Context, user domain.HubUser) (domain.HubUser, error) {
	const query = `
		INSERT INTO hub_users (
			email,
			display_name,
			access_level,
			status,
			password_hash,
			password_set_at,
			two_factor_required
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT ((lower(email))) DO UPDATE
		SET display_name = EXCLUDED.display_name,
			access_level = EXCLUDED.access_level,
			status = EXCLUDED.status,
			password_hash = CASE WHEN EXCLUDED.password_hash <> '' THEN EXCLUDED.password_hash ELSE hub_users.password_hash END,
			password_set_at = CASE WHEN EXCLUDED.password_hash <> '' THEN EXCLUDED.password_set_at ELSE hub_users.password_set_at END,
			two_factor_required = EXCLUDED.two_factor_required,
			updated_at = now()
		RETURNING ` + hubUserColumns + `
	`
	return scanHubUser(r.pool.QueryRow(
		ctx,
		query,
		user.Email,
		user.DisplayName,
		user.AccessLevel,
		user.Status,
		user.PasswordHash,
		user.PasswordSetAt,
		user.TwoFactorRequired,
	))
}

func (r *HubUserRepository) ListHubUsers(ctx context.Context) ([]domain.HubUser, error) {
	const query = `
		SELECT ` + hubUserColumns + `
		FROM hub_users
		ORDER BY
			CASE access_level
				WHEN 'owner' THEN 1
				WHEN 'admin' THEN 2
				WHEN 'operator' THEN 3
				ELSE 4
			END,
			email
	`
	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []domain.HubUser
	for rows.Next() {
		user, err := scanHubUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, rows.Err()
}

func (r *HubUserRepository) CountHubUsers(ctx context.Context) (int, error) {
	var count int
	err := r.pool.QueryRow(ctx, `SELECT count(*) FROM hub_users`).Scan(&count)
	return count, err
}

func (r *HubUserRepository) FindHubUserByEmail(ctx context.Context, email string) (domain.HubUser, bool, error) {
	user, err := scanHubUser(r.pool.QueryRow(ctx, `SELECT `+hubUserColumns+` FROM hub_users WHERE lower(email) = lower($1)`, email))
	if err == pgx.ErrNoRows {
		return domain.HubUser{}, false, nil
	}
	if err != nil {
		return domain.HubUser{}, false, err
	}
	return user, true, nil
}

func (r *HubUserRepository) FindHubUserByID(ctx context.Context, userID domain.ID) (domain.HubUser, bool, error) {
	user, err := scanHubUser(r.pool.QueryRow(ctx, `SELECT `+hubUserColumns+` FROM hub_users WHERE id = $1`, userID))
	if err == pgx.ErrNoRows {
		return domain.HubUser{}, false, nil
	}
	if err != nil {
		return domain.HubUser{}, false, err
	}
	return user, true, nil
}

func (r *HubUserRepository) UpdateHubUser(ctx context.Context, userID domain.ID, update domain.HubUserUpdate) (domain.HubUser, error) {
	const query = `
		UPDATE hub_users
		SET display_name = $2,
			access_level = $3,
			status = $4,
			two_factor_required = $5,
			updated_at = now()
		WHERE id = $1
		RETURNING ` + hubUserColumns + `
	`
	return scanHubUser(r.pool.QueryRow(
		ctx,
		query,
		userID,
		update.DisplayName,
		update.AccessLevel,
		update.Status,
		update.TwoFactorRequired,
	))
}

func (r *HubUserRepository) StartHubUserTOTP(ctx context.Context, userID domain.ID, start domain.HubUserTOTPStart) (domain.HubUser, error) {
	const query = `
		UPDATE hub_users
		SET pending_totp_secret_ciphertext = $2,
			pending_totp_started_at = $3,
			updated_at = now()
		WHERE id = $1
		RETURNING ` + hubUserColumns + `
	`
	return scanHubUser(r.pool.QueryRow(ctx, query, userID, start.PendingSecretCiphertext, start.StartedAt))
}

func (r *HubUserRepository) ActivateHubUserTOTP(ctx context.Context, userID domain.ID, activation domain.HubUserTOTPActivation) (domain.HubUser, error) {
	const query = `
		UPDATE hub_users
		SET totp_secret_ciphertext = $2,
			two_factor_enabled = true,
			two_factor_required = true,
			totp_enrolled_at = $3,
			pending_totp_secret_ciphertext = '',
			pending_totp_started_at = NULL,
			updated_at = now()
		WHERE id = $1
		RETURNING ` + hubUserColumns + `
	`
	return scanHubUser(r.pool.QueryRow(ctx, query, userID, activation.ActiveSecretCiphertext, activation.EnrolledAt))
}

func (r *HubUserRepository) DisableHubUserTOTP(ctx context.Context, userID domain.ID) (domain.HubUser, error) {
	const query = `
		UPDATE hub_users
		SET totp_secret_ciphertext = '',
			two_factor_enabled = false,
			totp_enrolled_at = NULL,
			pending_totp_secret_ciphertext = '',
			pending_totp_started_at = NULL,
			updated_at = now()
		WHERE id = $1
		RETURNING ` + hubUserColumns + `
	`
	return scanHubUser(r.pool.QueryRow(ctx, query, userID))
}

func (r *HubUserRepository) SaveHubUserSession(ctx context.Context, session domain.HubUserSession) (domain.HubUserSession, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return domain.HubUserSession{}, err
	}
	defer tx.Rollback(ctx)

	const insertQuery = `
		INSERT INTO hub_user_sessions (user_id, token_hash, expires_at, created_at, last_seen_at)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id::text, user_id::text, token_hash, expires_at, revoked_at, created_at, last_seen_at
	`
	var saved domain.HubUserSession
	err = tx.QueryRow(ctx, insertQuery, session.UserID, session.TokenHash, session.ExpiresAt, session.CreatedAt, session.LastSeenAt).Scan(
		&saved.ID,
		&saved.UserID,
		&saved.TokenHash,
		&saved.ExpiresAt,
		&saved.RevokedAt,
		&saved.CreatedAt,
		&saved.LastSeenAt,
	)
	if err != nil {
		return domain.HubUserSession{}, err
	}
	if _, err := tx.Exec(ctx, `UPDATE hub_users SET last_login_at = $2, updated_at = now() WHERE id = $1`, session.UserID, session.CreatedAt); err != nil {
		return domain.HubUserSession{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.HubUserSession{}, err
	}
	return saved, nil
}

func (r *HubUserRepository) FindHubUserBySessionTokenHash(ctx context.Context, tokenHash string, now time.Time) (domain.HubUser, domain.HubUserSession, bool, error) {
	const query = `
		SELECT
			u.id::text, u.email, u.display_name, u.access_level, u.status, u.password_hash, u.password_set_at,
			u.two_factor_required, u.two_factor_enabled, u.totp_secret_ciphertext,
			u.totp_enrolled_at, u.pending_totp_secret_ciphertext, u.pending_totp_started_at,
			u.last_login_at, u.created_at, u.updated_at,
			s.id::text, s.user_id::text, s.token_hash, s.expires_at, s.revoked_at, s.created_at, s.last_seen_at
		FROM hub_user_sessions s
		JOIN hub_users u ON u.id = s.user_id
		WHERE s.token_hash = $1
			AND s.revoked_at IS NULL
			AND s.expires_at > $2
	`
	row := r.pool.QueryRow(ctx, query, tokenHash, now)
	var user domain.HubUser
	var session domain.HubUserSession
	err := row.Scan(
		&user.ID,
		&user.Email,
		&user.DisplayName,
		&user.AccessLevel,
		&user.Status,
		&user.PasswordHash,
		&user.PasswordSetAt,
		&user.TwoFactorRequired,
		&user.TwoFactorEnabled,
		&user.TOTPSecretCiphertext,
		&user.TOTPEnrolledAt,
		&user.PendingTOTPSecretCiphertext,
		&user.PendingTOTPStartedAt,
		&user.LastLoginAt,
		&user.CreatedAt,
		&user.UpdatedAt,
		&session.ID,
		&session.UserID,
		&session.TokenHash,
		&session.ExpiresAt,
		&session.RevokedAt,
		&session.CreatedAt,
		&session.LastSeenAt,
	)
	if err == pgx.ErrNoRows {
		return domain.HubUser{}, domain.HubUserSession{}, false, nil
	}
	if err != nil {
		return domain.HubUser{}, domain.HubUserSession{}, false, err
	}
	return user, session, true, nil
}

func (r *HubUserRepository) TouchHubUserSession(ctx context.Context, tokenHash string, seenAt time.Time) error {
	_, err := r.pool.Exec(ctx, `UPDATE hub_user_sessions SET last_seen_at = $2 WHERE token_hash = $1 AND revoked_at IS NULL`, tokenHash, seenAt)
	return err
}

func (r *HubUserRepository) RevokeHubUserSession(ctx context.Context, tokenHash string, revokedAt time.Time) error {
	_, err := r.pool.Exec(ctx, `UPDATE hub_user_sessions SET revoked_at = $2 WHERE token_hash = $1 AND revoked_at IS NULL`, tokenHash, revokedAt)
	return err
}

const hubUserColumns = `id::text, email, display_name, access_level, status, password_hash, password_set_at,
	two_factor_required, two_factor_enabled, totp_secret_ciphertext,
	totp_enrolled_at, pending_totp_secret_ciphertext, pending_totp_started_at,
	last_login_at, created_at, updated_at`

type hubUserScanner interface {
	Scan(dest ...any) error
}

func scanHubUser(row hubUserScanner) (domain.HubUser, error) {
	var user domain.HubUser
	err := row.Scan(
		&user.ID,
		&user.Email,
		&user.DisplayName,
		&user.AccessLevel,
		&user.Status,
		&user.PasswordHash,
		&user.PasswordSetAt,
		&user.TwoFactorRequired,
		&user.TwoFactorEnabled,
		&user.TOTPSecretCiphertext,
		&user.TOTPEnrolledAt,
		&user.PendingTOTPSecretCiphertext,
		&user.PendingTOTPStartedAt,
		&user.LastLoginAt,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	return user, err
}
