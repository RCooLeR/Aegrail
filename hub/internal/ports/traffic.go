package ports

import (
	"context"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
)

// TrafficRepository is deliberately separate from IngestRepository. Traffic
// screens are optional and lazy-loaded, while ingest remains a core Hub path.
type TrafficRepository interface {
	GetTrafficOverview(ctx context.Context, filter domain.TrafficFilter) (domain.TrafficOverview, error)
	GetTrafficIPDetail(ctx context.Context, filter domain.TrafficFilter, ip string) (domain.TrafficIPDetail, bool, error)
	GetTrafficUserAgentDetail(ctx context.Context, filter domain.TrafficFilter, hash string) (domain.TrafficUserAgentDetail, bool, error)
	ListTrafficBots(ctx context.Context, filter domain.TrafficFilter) (domain.TrafficBotsPage, error)
	GetTrafficIPIntel(ctx context.Context, organizationID domain.ID, ip string) (domain.TrafficIPIntel, bool, error)
	SaveTrafficIPIntel(ctx context.Context, organizationID domain.ID, intel domain.TrafficIPIntel) (domain.TrafficIPIntel, error)
	GetTrafficIPPolicy(ctx context.Context, organizationID domain.ID, ip string) (domain.TrafficIPPolicy, bool, error)
	SaveTrafficIPPolicy(ctx context.Context, organizationID domain.ID, policy domain.TrafficIPPolicy) (domain.TrafficIPPolicy, error)
}

// TrafficBackfillRepository is optional. PostgreSQL implements it so a Hub
// upgraded from a pre-traffic schema can project recent access events through
// the same typed Go projection and user-agent classifier used by live ingest.
type TrafficBackfillRepository interface {
	BackfillRecentTrafficBatch(ctx context.Context, since time.Time, until time.Time, limit int) (int, error)
}
