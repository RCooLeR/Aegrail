package ports

import (
	"context"

	"github.com/rcooler/aegrail/hub/internal/domain"
)

type HubMaintenanceRepository interface {
	PruneHubData(ctx context.Context, options domain.HubMaintenancePruneOptions) (domain.HubMaintenancePruneResult, error)
	GetHubSystemStatus(ctx context.Context) (domain.HubSystemStatus, error)
}
