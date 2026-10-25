package notifications

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/rcooler/aegrail/hub/internal/ports"
)

type blockingNotificationSink struct {
	started chan<- struct{}
	release <-chan struct{}
}

type recordingNotificationSink struct {
	mu    sync.Mutex
	calls int
}

func (s *recordingNotificationSink) NotifyHubFinding(context.Context, ports.HubFindingNotification) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	return nil
}

func (s blockingNotificationSink) NotifyHubFinding(context.Context, ports.HubFindingNotification) error {
	s.started <- struct{}{}
	<-s.release
	return nil
}

func TestNamedFanoutDeliversOnlyRequestedTransport(t *testing.T) {
	email := &recordingNotificationSink{}
	webpush := &recordingNotificationSink{}
	sink := NewNamedFanoutSink(
		NamedSink{Name: "webpush", Sink: webpush},
		NamedSink{Name: "email", Sink: email},
	)
	transportSink, ok := sink.(ports.NotificationTransportSink)
	if !ok {
		t.Fatal("named fanout does not implement NotificationTransportSink")
	}
	if transports := transportSink.NotificationTransports(); len(transports) != 2 || transports[0] != "email" || transports[1] != "webpush" {
		t.Fatalf("transports = %#v, want sorted email/webpush", transports)
	}
	if err := transportSink.NotifyHubFindingTransport(context.Background(), "email", ports.HubFindingNotification{}); err != nil {
		t.Fatalf("NotifyHubFindingTransport returned error: %v", err)
	}
	if email.calls != 1 || webpush.calls != 0 {
		t.Fatalf("email calls=%d webpush calls=%d, want 1/0", email.calls, webpush.calls)
	}
}

func TestFanoutNotifiesTransportsConcurrently(t *testing.T) {
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	sink := NewFanoutSink(
		blockingNotificationSink{started: started, release: release},
		blockingNotificationSink{started: started, release: release},
	)
	done := make(chan error, 1)
	go func() {
		done <- sink.NotifyHubFinding(context.Background(), ports.HubFindingNotification{})
	}()

	for index := range 2 {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatalf("notification transport %d did not start concurrently", index+1)
		}
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("NotifyHubFinding returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("NotifyHubFinding did not finish after transports completed")
	}
}
