package httpadapter

import (
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/go-chi/chi/v5"
)

func mountDashboard(router chi.Router, dashboardDir string) {
	dashboardDir = strings.TrimSpace(dashboardDir)
	if dashboardDir == "" {
		return
	}

	fileServer := http.StripPrefix("/dashboard/", http.FileServer(http.Dir(dashboardDir)))
	router.Get("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dashboard/", http.StatusMovedPermanently)
	})
	router.Get("/dashboard/*", func(w http.ResponseWriter, r *http.Request) {
		requested := strings.TrimPrefix(path.Clean("/"+chi.URLParam(r, "*")), "/")
		if dashboardAssetExists(dashboardDir, requested) {
			fileServer.ServeHTTP(w, r)
			return
		}
		serveDashboardIndex(w, r, dashboardDir)
	})
}

func dashboardAssetExists(dashboardDir string, requested string) bool {
	if requested == "" || requested == "." {
		return false
	}
	fullPath := filepath.Join(dashboardDir, filepath.FromSlash(requested))
	info, err := os.Stat(fullPath)
	return err == nil && !info.IsDir()
}

func serveDashboardIndex(w http.ResponseWriter, r *http.Request, dashboardDir string) {
	http.ServeFile(w, r, filepath.Join(dashboardDir, "index.html"))
}
