package ports

import (
	"context"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
)

type IngestRepository interface {
	SaveIngestBatch(ctx context.Context, batch domain.IngestBatch, events []domain.IngestEvent) (domain.IngestBatch, []domain.IngestEvent, bool, error)
	ListIngestBatches(ctx context.Context, environmentID domain.ID, limit int) ([]domain.IngestBatch, error)
	ListFileStateObservations(ctx context.Context, environmentID domain.ID, appID domain.ID, since time.Time, limit int) ([]domain.FileStateObservation, error)
	ListTimelineEvents(ctx context.Context, environmentID domain.ID, appID domain.ID, since time.Time, limit int) ([]domain.TimelineEvent, error)
	ListTimelineEventsByID(ctx context.Context, environmentID domain.ID, appID domain.ID, eventIDs []domain.ID) ([]domain.TimelineEvent, error)
}

type IngestTimelineEventTypeRepository interface {
	ListTimelineEventsByTypes(ctx context.Context, environmentID domain.ID, appID domain.ID, since time.Time, eventTypes []string, limit int) ([]domain.TimelineEvent, error)
}

type IngestCorrelationTimelineRepository interface {
	ListCorrelationTimelineEvents(ctx context.Context, environmentID domain.ID, appID domain.ID, since time.Time, limit int) ([]domain.TimelineEvent, error)
}
