package hub

import (
	"bytes"
	"context"
	"runtime/pprof"
	"strings"
	"testing"
)

func TestRunHubWorkerPublishesGoroutineProfileLabel(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})

	go func() {
		runHubWorker(context.Background(), "profile-test", func(context.Context) {
			close(started)
			<-release
		})
		close(done)
	}()

	<-started
	var profile bytes.Buffer
	if err := pprof.Lookup("goroutine").WriteTo(&profile, 1); err != nil {
		close(release)
		<-done
		t.Fatalf("write goroutine profile: %v", err)
	}
	close(release)
	<-done

	output := profile.String()
	if !strings.Contains(output, `"aegrail.worker":"profile-test"`) {
		t.Fatalf("goroutine profile does not contain worker label:\n%s", output)
	}
}
