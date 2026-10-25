package httpadapter

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"
	hubapp "github.com/rcooler/aegrail/hub/internal/hub"
)

type updateTrafficIPPolicyRequest struct {
	Policy string `json:"policy"`
	Reason string `json:"reason"`
}

func getTrafficHandler(hub *hubapp.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			writeError(w, http.StatusServiceUnavailable, "hub is not configured")
			return
		}
		input, err := trafficQueryInputFromRequest(r)
		if err != nil {
			writeHubError(w, err)
			return
		}
		traffic, err := hub.GetTrafficOverview(r.Context(), input)
		if err != nil {
			writeHubError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"traffic": traffic})
	}
}

func getTrafficIPHandler(hub *hubapp.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			writeError(w, http.StatusServiceUnavailable, "hub is not configured")
			return
		}
		query, err := trafficQueryInputFromRequest(r)
		if err != nil {
			writeHubError(w, err)
			return
		}
		ip, err := trafficIPPathParameter(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "valid IP address is required")
			return
		}
		detail, err := hub.GetTrafficIPDetail(r.Context(), hubapp.TrafficIPInput{
			TrafficQueryInput: query,
			IP:                ip,
		})
		if err != nil {
			writeHubError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ip": detail})
	}
}

func updateTrafficIPPolicyHandler(hub *hubapp.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			writeError(w, http.StatusServiceUnavailable, "hub is not configured")
			return
		}
		var request updateTrafficIPPolicyRequest
		if err := decodeJSONBody(w, r, &request); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		ip, err := trafficIPPathParameter(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "valid IP address is required")
			return
		}
		actor := ""
		if user, ok := currentHubUser(r); ok {
			actor = strings.TrimSpace(user.Email)
			if actor == "" {
				actor = strings.TrimSpace(user.DisplayName)
			}
		}
		policy, err := hub.UpdateTrafficIPPolicy(r.Context(), hubapp.UpdateTrafficIPPolicyInput{
			OrganizationSlug: r.URL.Query().Get("org"),
			ProjectSlug:      r.URL.Query().Get("project"),
			EnvironmentSlug:  r.URL.Query().Get("environment"),
			AppSlug:          r.URL.Query().Get("app"),
			IP:               ip,
			Policy:           request.Policy,
			Reason:           request.Reason,
			Actor:            actor,
		})
		if err != nil {
			writeHubError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"policy": policy})
	}
}

func getTrafficUserAgentHandler(hub *hubapp.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			writeError(w, http.StatusServiceUnavailable, "hub is not configured")
			return
		}
		query, err := trafficQueryInputFromRequest(r)
		if err != nil {
			writeHubError(w, err)
			return
		}
		detail, err := hub.GetTrafficUserAgentDetail(r.Context(), hubapp.TrafficUserAgentInput{
			TrafficQueryInput: query,
			Hash:              chi.URLParam(r, "hash"),
		})
		if err != nil {
			writeHubError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"user_agent": detail})
	}
}

func listTrafficBotsHandler(hub *hubapp.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			writeError(w, http.StatusServiceUnavailable, "hub is not configured")
			return
		}
		input, err := trafficQueryInputFromRequest(r)
		if err != nil {
			writeHubError(w, err)
			return
		}
		result, err := hub.ListTrafficBots(r.Context(), input)
		if err != nil {
			writeHubError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"since":                   result.Since,
			"until":                   result.Until,
			"total_clients":           result.TotalClients,
			"total_requests":          result.TotalRequests,
			"total_verified_requests": result.TotalVerifiedRequests,
			"total_error_requests":    result.TotalErrorRequests,
			"returned":                result.Returned,
			"truncated":               result.Truncated,
			"bots":                    result.Bots,
		})
	}
}

func trafficQueryInputFromRequest(r *http.Request) (hubapp.TrafficQueryInput, error) {
	limit, err := parseQueryLimit(r, defaultTrafficHTTPQueryLimit)
	if err != nil {
		return hubapp.TrafficQueryInput{}, err
	}
	since, err := parseQueryTime(r.URL.Query().Get("since"), "since")
	if err != nil {
		return hubapp.TrafficQueryInput{}, err
	}
	until, err := parseQueryTime(r.URL.Query().Get("until"), "until")
	if err != nil {
		return hubapp.TrafficQueryInput{}, err
	}
	return hubapp.TrafficQueryInput{
		OrganizationSlug: r.URL.Query().Get("org"),
		ProjectSlug:      r.URL.Query().Get("project"),
		EnvironmentSlug:  r.URL.Query().Get("environment"),
		AppSlug:          r.URL.Query().Get("app"),
		Since:            since,
		Until:            until,
		Limit:            limit,
	}, nil
}

const defaultTrafficHTTPQueryLimit = 25

func trafficIPPathParameter(r *http.Request) (string, error) {
	return url.PathUnescape(chi.URLParam(r, "ip"))
}
