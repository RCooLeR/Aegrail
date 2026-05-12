package ports

import (
	"context"

	"github.com/rcooler/aegrail/internal/domain"
)

type HubFindingRepository interface {
	SaveHubFindings(ctx context.Context, findings []domain.HubFinding) ([]domain.HubFinding, error)
	ListHubFindings(ctx context.Context, environmentID domain.ID, appID domain.ID, limit int) ([]domain.HubFinding, error)
	UpdateHubFindingStatus(ctx context.Context, findingID domain.ID, environmentID domain.ID, update domain.HubFindingStatusUpdate) (domain.HubFinding, error)
}
