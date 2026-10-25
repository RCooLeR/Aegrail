package hub

import (
	"context"
	"time"

	"github.com/rcooler/aegrail/hub/internal/ports"
)

const (
	defaultTrafficBackfillWindow    = 30 * 24 * time.Hour
	defaultTrafficBackfillBatchSize = 500
	maximumTrafficBackfillBatchSize = 1000
	defaultTrafficBackfillYield     = 25 * time.Millisecond
)

// TrafficBackfillWorkerOptions controls the one-shot upgrade backfill. Each
// transaction is bounded by BatchSize, while the worker keeps yielding and
// continuing until every missing projection in the recent window is filled.
type TrafficBackfillWorkerOptions struct {
	Window     time.Duration
	BatchSize  int
	Yield      time.Duration
	Now        time.Time
	OnBatch    func(projected int, totalProjected int)
	OnComplete func(totalProjected int)
	OnError    func(error)
}

func (h *Hub) StartTrafficBackfillWorker(ctx context.Context, options TrafficBackfillWorkerOptions) bool {
	if h == nil || h.traffic == nil {
		return false
	}
	repository, ok := h.traffic.(ports.TrafficBackfillRepository)
	if !ok {
		return false
	}
	options = normalizeTrafficBackfillWorkerOptions(options)
	h.workersWG.Add(1)
	go runHubWorker(ctx, "traffic-backfill", func(ctx context.Context) {
		defer h.workersWG.Done()
		h.runTrafficBackfillWorker(ctx, repository, options)
	})
	return true
}

func (h *Hub) runTrafficBackfillWorker(ctx context.Context, repository ports.TrafficBackfillRepository, options TrafficBackfillWorkerOptions) {
	until := options.Now
	if until.IsZero() {
		until = time.Now().UTC()
	} else {
		until = until.UTC()
	}
	since := until.Add(-options.Window)
	totalProjected := 0
	for {
		projected, err := repository.BackfillRecentTrafficBatch(ctx, since, until, options.BatchSize)
		if err != nil {
			if ctx.Err() == nil {
				if options.OnError != nil {
					options.OnError(err)
				} else if h.backgroundError != nil {
					h.backgroundError(err)
				}
			}
			return
		}
		if projected <= 0 {
			if options.OnComplete != nil {
				options.OnComplete(totalProjected)
			}
			return
		}
		totalProjected += projected
		if options.OnBatch != nil {
			options.OnBatch(projected, totalProjected)
		}
		timer := time.NewTimer(options.Yield)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func normalizeTrafficBackfillWorkerOptions(options TrafficBackfillWorkerOptions) TrafficBackfillWorkerOptions {
	if options.Window <= 0 || options.Window > defaultTrafficBackfillWindow {
		options.Window = defaultTrafficBackfillWindow
	}
	if options.BatchSize <= 0 {
		options.BatchSize = defaultTrafficBackfillBatchSize
	}
	if options.BatchSize > maximumTrafficBackfillBatchSize {
		options.BatchSize = maximumTrafficBackfillBatchSize
	}
	if options.Yield <= 0 {
		options.Yield = defaultTrafficBackfillYield
	}
	return options
}
