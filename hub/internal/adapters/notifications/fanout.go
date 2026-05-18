package notifications

import (
	"context"
	"errors"

	"github.com/rcooler/aegrail/hub/internal/ports"
)

type FanoutSink struct {
	sinks []ports.NotificationSink
}

func NewFanoutSink(sinks ...ports.NotificationSink) ports.NotificationSink {
	filtered := make([]ports.NotificationSink, 0, len(sinks))
	for _, sink := range sinks {
		if sink != nil {
			filtered = append(filtered, sink)
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	return &FanoutSink{sinks: filtered}
}

func (s *FanoutSink) NotifyHubFinding(ctx context.Context, notification ports.HubFindingNotification) error {
	if s == nil {
		return nil
	}
	var errs []error
	for _, sink := range s.sinks {
		if err := sink.NotifyHubFinding(ctx, notification); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
