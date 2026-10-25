package hub

import (
	"context"
	"errors"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
)

type MaintenanceOptions struct {
	EventRetention           time.Duration
	ResolvedFindingRetention time.Duration
	ModelReportRetention     time.Duration
	AuthEventRetention       time.Duration
	BatchSize                int
	Now                      time.Time
}

type MaintenanceWorkerOptions struct {
	Interval                 time.Duration
	EventRetention           time.Duration
	ResolvedFindingRetention time.Duration
	ModelReportRetention     time.Duration
	AuthEventRetention       time.Duration
	BatchSize                int
	OnRun                    func(domain.HubMaintenancePruneResult)
	OnError                  func(error)
}

func (h *Hub) PruneHubData(ctx context.Context, options MaintenanceOptions) (domain.HubMaintenancePruneResult, error) {
	if h == nil || h.maintenance == nil {
		return domain.HubMaintenancePruneResult{}, errors.New("hub maintenance repository is not configured")
	}
	now := options.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return h.maintenance.PruneHubData(ctx, domain.HubMaintenancePruneOptions{
		Now:                      now,
		EventRetention:           options.EventRetention,
		ResolvedFindingRetention: options.ResolvedFindingRetention,
		ModelReportRetention:     options.ModelReportRetention,
		AuthEventRetention:       options.AuthEventRetention,
		BatchSize:                options.BatchSize,
	})
}

func (h *Hub) GetHubSystemStatus(ctx context.Context) (domain.HubSystemStatus, error) {
	if h == nil || h.maintenance == nil {
		return domain.HubSystemStatus{}, errors.New("hub maintenance repository is not configured")
	}
	return h.maintenance.GetHubSystemStatus(ctx)
}

func (h *Hub) StartMaintenanceWorker(ctx context.Context, options MaintenanceWorkerOptions) {
	if h == nil || h.maintenance == nil {
		return
	}
	interval := options.Interval
	if interval <= 0 {
		interval = time.Hour
	}
	h.workersWG.Add(1)
	go runHubWorker(ctx, "maintenance", func(ctx context.Context) {
		defer h.workersWG.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		run := func() {
			runCtx, cancel := context.WithTimeout(ctx, minDuration(interval, 30*time.Minute))
			defer cancel()
			result, err := h.PruneHubData(runCtx, MaintenanceOptions{
				EventRetention:           options.EventRetention,
				ResolvedFindingRetention: options.ResolvedFindingRetention,
				ModelReportRetention:     options.ModelReportRetention,
				AuthEventRetention:       options.AuthEventRetention,
				BatchSize:                options.BatchSize,
			})
			if err != nil {
				if options.OnError != nil {
					options.OnError(err)
				} else if h.backgroundError != nil {
					h.backgroundError(err)
				}
				return
			}
			if options.OnRun != nil {
				options.OnRun(result)
			}
		}
		run()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				run()
			}
		}
	})
}

func minDuration(a time.Duration, b time.Duration) time.Duration {
	if a <= 0 {
		return b
	}
	if b <= 0 || a < b {
		return a
	}
	return b
}
