package cli

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
	urfavecli "github.com/urfave/cli/v3"
)

type hubShutdownContextKey struct{}

func runCLICapture(t *testing.T, args ...string) string {
	t.Helper()
	app := New(domain.AppMeta{Name: "Aegrail Hub", Binary: "hub", Version: "test"})
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app.Writer = &stdout
	app.ErrWriter = &stderr
	if err := app.Run(context.Background(), args); err != nil {
		t.Fatalf("Run(%v) returned error: %v\nstdout:\n%s\nstderr:\n%s", args, err, stdout.String(), stderr.String())
	}
	return stdout.String()
}

func TestHealthcheckCommandIsRegistered(t *testing.T) {
	output := runCLICapture(t, "hub", "healthcheck", "--help")
	if !bytes.Contains([]byte(output), []byte("check Hub dependencies")) {
		t.Fatalf("healthcheck help = %q, want usage text", output)
	}
}

func TestHubHTTPServerConfiguration(t *testing.T) {
	handler := http.NewServeMux()
	server := newHubHTTPServer("127.0.0.1:8787", handler)

	if server.Handler != handler {
		t.Fatal("Handler was not preserved")
	}
	if server.MaxHeaderValueCount != hubMaxHeaderValueCount {
		t.Fatalf("MaxHeaderValueCount = %d, want %d", server.MaxHeaderValueCount, hubMaxHeaderValueCount)
	}
	if server.ReadHeaderTimeout != 5*time.Second || server.ReadTimeout != 15*time.Second ||
		server.WriteTimeout != 60*time.Second || server.IdleTimeout != 60*time.Second {
		t.Fatalf("unexpected server timeouts: %#v", server)
	}
}

func TestHubShutdownContextSurvivesCancellationAndPreservesValues(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.WithValue(context.Background(), hubShutdownContextKey{}, "request-42"))
	cancelParent()

	shutdownCtx, cancelShutdown := newHubShutdownContext(parent)
	defer cancelShutdown()

	if err := shutdownCtx.Err(); err != nil {
		t.Fatalf("shutdown context inherited cancellation: %v", err)
	}
	if errors.Is(context.Cause(shutdownCtx), context.Canceled) {
		t.Fatalf("shutdown context inherited cancellation cause: %v", context.Cause(shutdownCtx))
	}
	if got := shutdownCtx.Value(hubShutdownContextKey{}); got != "request-42" {
		t.Fatalf("shutdown context value = %v, want request-42", got)
	}
	deadline, ok := shutdownCtx.Deadline()
	if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > hubGracefulStopTimeout {
		t.Fatalf("shutdown deadline = %v, want within %s", deadline, hubGracefulStopTimeout)
	}
}

func TestHubServeUsesEnvironmentValueSources(t *testing.T) {
	t.Setenv("AEGRAIL_HTTP_ADDR", "127.0.0.1:9876")

	serve := hubServeCommand(domain.AppMeta{Name: "Aegrail Hub", Binary: "hub", Version: "test"})
	var addr string
	serve.Action = func(_ context.Context, command *urfavecli.Command) error {
		addr = command.String("addr")
		return nil
	}
	root := &urfavecli.Command{Name: "hub", Commands: []*urfavecli.Command{serve}}
	if err := root.Run(context.Background(), []string{"hub", "serve"}); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if addr != "127.0.0.1:9876" {
		t.Fatalf("addr = %q, want environment value", addr)
	}
}

func TestHubHealthStatus(t *testing.T) {
	status, healthy := hubHealthStatus(map[string]string{
		"database": "ok",
		"redis":    "ok",
		"ollama":   "unavailable",
	})
	if status != "degraded" || !healthy {
		t.Fatalf("status=%s healthy=%t, want degraded healthy for optional ollama failure", status, healthy)
	}

	status, healthy = hubHealthStatus(map[string]string{
		"database": "error",
		"ollama":   "ok: qwen2.5-coder:14b",
	})
	if status != "unhealthy" || healthy {
		t.Fatalf("status=%s healthy=%t, want unhealthy for database failure", status, healthy)
	}
}
