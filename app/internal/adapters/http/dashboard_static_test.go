package httpadapter

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rcooler/aegrail/internal/domain"
	hubapp "github.com/rcooler/aegrail/internal/hub"
)

func TestHubRouterServesDashboardAssets(t *testing.T) {
	dashboardDir := t.TempDir()
	assetsDir := filepath.Join(dashboardDir, "assets")
	if err := os.Mkdir(assetsDir, 0o700); err != nil {
		t.Fatalf("Mkdir returned error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dashboardDir, "index.html"), []byte(`<div id="root"></div>`), 0o600); err != nil {
		t.Fatalf("WriteFile index returned error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(assetsDir, "app.js"), []byte(`console.log("dashboard")`), 0o600); err != nil {
		t.Fatalf("WriteFile asset returned error: %v", err)
	}

	router := NewHubRouter(
		domain.AppMeta{Name: "Aegrail", Binary: "aegrail", Version: "test"},
		hubapp.New(hubapp.Dependencies{}),
		HubOptions{DashboardDir: dashboardDir},
	)

	assetResponse := httptest.NewRecorder()
	router.ServeHTTP(assetResponse, httptest.NewRequest(http.MethodGet, "/dashboard/assets/app.js", nil))
	if assetResponse.Code != http.StatusOK {
		t.Fatalf("asset status = %d body = %s", assetResponse.Code, assetResponse.Body.String())
	}
	if !strings.Contains(assetResponse.Body.String(), "dashboard") {
		t.Fatalf("asset body = %q, want dashboard asset", assetResponse.Body.String())
	}

	spaResponse := httptest.NewRecorder()
	router.ServeHTTP(spaResponse, httptest.NewRequest(http.MethodGet, "/dashboard/findings", nil))
	if spaResponse.Code != http.StatusOK {
		t.Fatalf("spa status = %d body = %s", spaResponse.Code, spaResponse.Body.String())
	}
	if !strings.Contains(spaResponse.Body.String(), `id="root"`) {
		t.Fatalf("spa body = %q, want dashboard index", spaResponse.Body.String())
	}
}
