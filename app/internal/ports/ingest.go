package ports

import (
	"context"
	"time"

	"github.com/rcooler/aegrail/internal/domain"
)

type IngestRepository interface {
	SaveIngestBatch(ctx context.Context, batch domain.IngestBatch, events []domain.IngestEvent) (domain.IngestBatch, []domain.IngestEvent, bool, error)
	ListIngestBatches(ctx context.Context, environmentID domain.ID, limit int) ([]domain.IngestBatch, error)
	ListFileStateObservations(ctx context.Context, environmentID domain.ID, appID domain.ID, since time.Time, limit int) ([]domain.FileStateObservation, error)
	ListTimelineEvents(ctx context.Context, environmentID domain.ID, appID domain.ID, since time.Time, limit int) ([]domain.TimelineEvent, error)
}
