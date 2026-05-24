package hub

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/rcooler/aegrail/hub/internal/ports"
)

const (
	ingestCorrelationJobSchema = "aegrail.hub.job.ingest-correlation.v1"
	ingestCorrelationQueueName = "ingest-correlation"

	defaultCorrelationWorkerCount   = 1
	defaultCorrelationQueueTimeout  = 5 * time.Second
	defaultCorrelationWorkerBackoff = 2 * time.Second
	defaultCorrelationJobMaxAge     = 30 * time.Minute
)

type ingestCorrelationJob struct {
	Schema           string        `json:"schema"`
	OrganizationSlug string        `json:"organization_slug"`
	ProjectSlug      string        `json:"project_slug"`
	EnvironmentSlug  string        `json:"environment_slug"`
	AppSlug          string        `json:"app_slug,omitempty"`
	Since            time.Time     `json:"since"`
	Window           time.Duration `json:"window"`
	Limit            int           `json:"limit"`
	QueuedAt         time.Time     `json:"queued_at"`
}

type CorrelationWorkerOptions struct {
	Workers        int
	DequeueTimeout time.Duration
	OnError        func(error)
}

func (h *Hub) StartCorrelationWorker(ctx context.Context, options CorrelationWorkerOptions) bool {
	if h.jobs == nil {
		return false
	}
	workers := options.Workers
	if workers <= 0 {
		workers = defaultCorrelationWorkerCount
	}
	timeout := options.DequeueTimeout
	if timeout <= 0 {
		timeout = defaultCorrelationQueueTimeout
	}
	for range workers {
		h.workersWG.Add(1)
		go func() {
			defer h.workersWG.Done()
			h.runCorrelationWorker(ctx, timeout, options.OnError)
		}()
	}
	return true
}

func (h *Hub) WaitForWorkers() {
	if h == nil {
		return
	}
	h.workersWG.Wait()
}

func (h *Hub) runCorrelationWorker(ctx context.Context, timeout time.Duration, onError func(error)) {
	for {
		payload, err := h.jobs.Dequeue(ctx, ingestCorrelationQueueName, timeout)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if errors.Is(err, ports.ErrQueueTimeout) {
				continue
			}
			if onError != nil {
				onError(err)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(defaultCorrelationWorkerBackoff):
			}
			continue
		}
		if err := h.HandleCorrelationJob(ctx, payload); err != nil && onError != nil {
			onError(err)
		}
	}
}

func (h *Hub) HandleCorrelationJob(ctx context.Context, payload []byte) error {
	var job ingestCorrelationJob
	if err := json.Unmarshal(payload, &job); err != nil {
		return err
	}
	if job.Schema != "" && job.Schema != ingestCorrelationJobSchema {
		return nil
	}
	if !job.QueuedAt.IsZero() && time.Since(job.QueuedAt) > defaultCorrelationJobMaxAge {
		return nil
	}
	if !h.reserveAutoCorrelationRun(autoCorrelationScopeKey(job.OrganizationSlug, job.ProjectSlug, job.EnvironmentSlug, job.AppSlug), time.Now().UTC()) {
		return nil
	}
	window := job.Window
	if window <= 0 {
		window = autoCorrelationWindow
	}
	limit := job.Limit
	if limit <= 0 {
		limit = autoCorrelationLimit
	}
	since := job.Since
	if since.IsZero() {
		since = time.Now().UTC().Add(-autoCorrelationLookback)
	}
	_, err := h.CorrelateEvents(ctx, CorrelateEventsInput{
		OrganizationSlug: job.OrganizationSlug,
		ProjectSlug:      job.ProjectSlug,
		EnvironmentSlug:  job.EnvironmentSlug,
		AppSlug:          job.AppSlug,
		Since:            since,
		Window:           window,
		Limit:            limit,
		SaveFindings:     true,
	})
	return err
}
