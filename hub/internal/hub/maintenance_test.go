package hub

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
)

type fakeMaintenanceRepository struct {
	pruneResult domain.HubMaintenancePruneResult
	pruneError  error
	status      domain.HubSystemStatus
	options     chan domain.HubMaintenancePruneOptions
}

func (r *fakeMaintenanceRepository) PruneHubData(_ context.Context, options domain.HubMaintenancePruneOptions) (domain.HubMaintenancePruneResult, error) {
	if r.options != nil {
		r.options <- options
	}
	return r.pruneResult, r.pruneError
}

func (r *fakeMaintenanceRepository) GetHubSystemStatus(_ context.Context) (domain.HubSystemStatus, error) {
	return r.status, nil
}

func TestPruneHubDataForwardsRetentionOptions(t *testing.T) {
	now := time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)
	repository := &fakeMaintenanceRepository{
		pruneResult: domain.HubMaintenancePruneResult{IngestEventsDeleted: 3},
		options:     make(chan domain.HubMaintenancePruneOptions, 1),
	}
	h := New(Dependencies{Maintenance: repository})

	result, err := h.PruneHubData(context.Background(), MaintenanceOptions{
		Now:                      now,
		EventRetention:           180 * 24 * time.Hour,
		ResolvedFindingRetention: 90 * 24 * time.Hour,
		ModelReportRetention:     30 * 24 * time.Hour,
		AuthEventRetention:       14 * 24 * time.Hour,
		BatchSize:                123,
	})
	if err != nil {
		t.Fatalf("PruneHubData returned error: %v", err)
	}
	if result.IngestEventsDeleted != 3 {
		t.Fatalf("IngestEventsDeleted = %d, want 3", result.IngestEventsDeleted)
	}

	got := <-repository.options
	if got.Now != now ||
		got.EventRetention != 180*24*time.Hour ||
		got.ResolvedFindingRetention != 90*24*time.Hour ||
		got.ModelReportRetention != 30*24*time.Hour ||
		got.AuthEventRetention != 14*24*time.Hour ||
		got.BatchSize != 123 {
		t.Fatalf("forwarded options = %+v", got)
	}
}

func TestMaintenanceWorkerRunsImmediatelyAndReportsErrors(t *testing.T) {
	expected := errors.New("maintenance failed")
	repository := &fakeMaintenanceRepository{
		pruneError: expected,
		options:    make(chan domain.HubMaintenancePruneOptions, 1),
	}
	h := New(Dependencies{Maintenance: repository})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errorsSeen := make(chan error, 1)

	h.StartMaintenanceWorker(ctx, MaintenanceWorkerOptions{
		Interval: 10 * time.Hour,
		OnError:  func(err error) { errorsSeen <- err },
	})

	select {
	case err := <-errorsSeen:
		if !errors.Is(err, expected) {
			t.Fatalf("worker error = %v, want %v", err, expected)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("maintenance worker did not run immediately")
	}
	cancel()
	h.WaitForWorkers()
}
