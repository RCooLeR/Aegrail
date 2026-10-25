package hub

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestTrafficBackfillWorkerContinuesBoundedBatchesUntilComplete(t *testing.T) {
	repository := &memoryTrafficBackfillRepository{
		memoryTrafficRepository: newMemoryTrafficRepository(),
		results:                 []int{1000, 400, 0},
	}
	hub := New(Dependencies{Traffic: repository})
	now := time.Date(2026, 8, 4, 10, 0, 0, 0, time.UTC)
	complete := make(chan int, 1)

	if !hub.StartTrafficBackfillWorker(t.Context(), TrafficBackfillWorkerOptions{
		Window:     31 * 24 * time.Hour,
		BatchSize:  5000,
		Yield:      time.Millisecond,
		Now:        now,
		OnComplete: func(total int) { complete <- total },
	}) {
		t.Fatal("traffic backfill worker did not start")
	}

	select {
	case total := <-complete:
		if total != 1400 {
			t.Fatalf("completed total = %d, want 1400", total)
		}
	case <-time.After(time.Second):
		t.Fatal("traffic backfill worker did not complete")
	}

	repository.mu.Lock()
	defer repository.mu.Unlock()
	if len(repository.calls) != 3 {
		t.Fatalf("batch calls = %d, want 3", len(repository.calls))
	}
	for _, call := range repository.calls {
		if call.limit != maximumTrafficBackfillBatchSize {
			t.Fatalf("batch limit = %d, want bounded %d", call.limit, maximumTrafficBackfillBatchSize)
		}
		if !call.since.Equal(now.Add(-30*24*time.Hour)) || !call.until.Equal(now) {
			t.Fatalf("backfill window = %s..%s, want fixed recent 30d", call.since, call.until)
		}
	}
}

func TestTrafficBackfillWorkerReportsRepositoryError(t *testing.T) {
	wantErr := errors.New("projection failed")
	repository := &memoryTrafficBackfillRepository{
		memoryTrafficRepository: newMemoryTrafficRepository(),
		err:                     wantErr,
	}
	hub := New(Dependencies{Traffic: repository})
	errorsSeen := make(chan error, 1)

	if !hub.StartTrafficBackfillWorker(t.Context(), TrafficBackfillWorkerOptions{
		OnError: func(err error) { errorsSeen <- err },
	}) {
		t.Fatal("traffic backfill worker did not start")
	}
	select {
	case err := <-errorsSeen:
		if !errors.Is(err, wantErr) {
			t.Fatalf("worker error = %v, want %v", err, wantErr)
		}
	case <-time.After(time.Second):
		t.Fatal("traffic backfill worker did not report error")
	}
}

type trafficBackfillCall struct {
	since time.Time
	until time.Time
	limit int
}

type memoryTrafficBackfillRepository struct {
	*memoryTrafficRepository
	mu      sync.Mutex
	results []int
	err     error
	calls   []trafficBackfillCall
}

func (r *memoryTrafficBackfillRepository) BackfillRecentTrafficBatch(_ context.Context, since time.Time, until time.Time, limit int) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, trafficBackfillCall{since: since, until: until, limit: limit})
	if r.err != nil {
		return 0, r.err
	}
	if len(r.results) == 0 {
		return 0, nil
	}
	result := r.results[0]
	r.results = r.results[1:]
	return result, nil
}
