package ports

import (
	"context"
	"errors"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
)

var ErrHubTOTPChanged = errors.New("pending 2FA enrolment changed; start setup again")

var ErrHubNotFound = errors.New("resource not found")

var ErrHubLastOwner = errors.New("at least one active owner must remain")

var ErrHubUserExists = errors.New("hub user already exists")

var ErrAgentAlreadyProvisioned = errors.New("agent already has a wire public key; rotate the key explicitly")

type HubUserRepository interface {
	SaveHubUser(ctx context.Context, user domain.HubUser) (domain.HubUser, error)
	ListHubUsers(ctx context.Context) ([]domain.HubUser, error)
	CountHubUsers(ctx context.Context) (int, error)
	FindHubUserByEmail(ctx context.Context, email string) (domain.HubUser, bool, error)
	FindHubUserByID(ctx context.Context, userID domain.ID) (domain.HubUser, bool, error)
	UpdateHubUser(ctx context.Context, userID domain.ID, update domain.HubUserUpdate) (domain.HubUser, error)
	StartHubUserTOTP(ctx context.Context, userID domain.ID, start domain.HubUserTOTPStart) (domain.HubUser, error)
	ActivateHubUserTOTP(ctx context.Context, userID domain.ID, activation domain.HubUserTOTPActivation) (domain.HubUser, error)
	DisableHubUserTOTP(ctx context.Context, userID domain.ID) (domain.HubUser, error)
	SaveHubUserSession(ctx context.Context, session domain.HubUserSession) (domain.HubUserSession, error)
	FindHubUserBySessionTokenHash(ctx context.Context, tokenHash string, now time.Time) (domain.HubUser, domain.HubUserSession, bool, error)
	TouchHubUserSession(ctx context.Context, tokenHash string, seenAt time.Time) error
	RevokeHubUserSession(ctx context.Context, tokenHash string, revokedAt time.Time) error
}

type BootstrapHubUserRepository interface {
	CreateBootstrapHubUser(ctx context.Context, user domain.HubUser) (domain.HubUser, bool, error)
}

type DeleteHubUserRepository interface {
	DeleteHubUser(ctx context.Context, userID domain.ID) (remaining int, err error)
}
