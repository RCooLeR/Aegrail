package notifications

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/rcooler/aegrail/hub/internal/ports"
)

type NamedSink struct {
	Name string
	Sink ports.NotificationSink
}

type notificationTransport struct {
	name string
	sink ports.NotificationSink
}

type FanoutSink struct {
	transports []notificationTransport
}

func NewFanoutSink(sinks ...ports.NotificationSink) ports.NotificationSink {
	named := make([]NamedSink, 0, len(sinks))
	for index, sink := range sinks {
		if sink != nil {
			named = append(named, NamedSink{
				Name: fmt.Sprintf("sink-%d", index+1),
				Sink: sink,
			})
		}
	}
	return NewNamedFanoutSink(named...)
}

func NewNamedFanoutSink(sinks ...NamedSink) ports.NotificationSink {
	byName := make(map[string]ports.NotificationSink, len(sinks))
	for _, item := range sinks {
		name := strings.TrimSpace(item.Name)
		if name == "" || item.Sink == nil {
			continue
		}
		byName[name] = item.Sink
	}
	if len(byName) == 0 {
		return nil
	}
	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)
	transports := make([]notificationTransport, 0, len(names))
	for _, name := range names {
		transports = append(transports, notificationTransport{name: name, sink: byName[name]})
	}
	return &FanoutSink{transports: transports}
}

func (s *FanoutSink) NotificationTransports() []string {
	if s == nil {
		return nil
	}
	transports := make([]string, len(s.transports))
	for index, item := range s.transports {
		transports[index] = item.name
	}
	return transports
}

func (s *FanoutSink) NotifyHubFindingTransport(ctx context.Context, transport string, notification ports.HubFindingNotification) error {
	if s == nil {
		return nil
	}
	transport = strings.TrimSpace(transport)
	for _, item := range s.transports {
		if item.name == transport {
			return item.sink.NotifyHubFinding(ctx, notification)
		}
	}
	return fmt.Errorf("notification transport %q is not configured", transport)
}

func (s *FanoutSink) NotifyHubFinding(ctx context.Context, notification ports.HubFindingNotification) error {
	if s == nil {
		return nil
	}
	type result struct {
		index int
		err   error
	}
	results := make(chan result, len(s.transports))
	for index, item := range s.transports {
		go func() {
			results <- result{index: index, err: item.sink.NotifyHubFinding(ctx, notification)}
		}()
	}
	ordered := make([]error, len(s.transports))
	for range s.transports {
		item := <-results
		ordered[item.index] = item.err
	}
	errs := make([]error, 0, len(ordered))
	for _, err := range ordered {
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
