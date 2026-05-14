package ports

import (
	"context"
	"time"

	"github.com/rcooler/aegrail/internal/domain"
)

type HubUserRepository interface {
	SaveHubUser(ctx context.Context, user domain.HubUser) (domain.HubUser, error)
	ListHubUsers(ctx context.Context) ([]domain.HubUser, error)
	CountHubUsers(ctx context.Context) (int, error)
	FindHubUserByEmail(ctx context.Context, email string) (domain.HubUser, bool, error)
	FindHubUserByID(ctx context.Context, userID domain.ID) (domain.HubUser, bool, error)
	UpdateHubUser(ctx context.Context, userID domain.ID, update domain.HubUserUpdate) (domain.HubUser, error)
	UpdateHubUserTOTP(ctx context.Context, userID domain.ID, update domain.HubUserTOTPUpdate) (domain.HubUser, error)
	SaveHubUserSession(ctx context.Context, session domain.HubUserSession) (domain.HubUserSession, error)
	FindHubUserBySessionTokenHash(ctx context.Context, tokenHash string, now time.Time) (domain.HubUser, domain.HubUserSession, bool, error)
	TouchHubUserSession(ctx context.Context, tokenHash string, seenAt time.Time) error
	RevokeHubUserSession(ctx context.Context, tokenHash string, revokedAt time.Time) error
}
