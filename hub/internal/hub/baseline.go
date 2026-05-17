package hub

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
)

type CompareFileBaselinesInput struct {
	OrganizationSlug string
	ProjectSlug      string
	EnvironmentSlug  string
	AppSlug          string
	Since            time.Time
	Limit            int
}

type FileBaselineComparisonResult struct {
	Environment   domain.Environment
	App           domain.MonitoredApp
	Since         time.Time
	ObservedHosts []string
	Differences   []FileBaselineDifference
}

type FileBaselineDifference struct {
	RelativePath string
	Reason       string
	Severity     domain.Severity
	Hosts        []FileBaselineHostState
}

type FileBaselineHostState struct {
	HostSlug       string
	Hostname       string
	AgentID        string
	EventType      string
	EventTime      time.Time
	Path           string
	SHA256         string
	PreviousSHA256 string
	SizeBytes      int64
	HashSkipped    bool
	Deleted        bool
	Severity       domain.Severity
}

func (h *Hub) CompareFileBaselines(ctx context.Context, input CompareFileBaselinesInput) (FileBaselineComparisonResult, error) {
	if h.ingest == nil {
		return FileBaselineComparisonResult{}, errors.New("ingest repository is not configured")
	}
	if err := h.requireInventory(); err != nil {
		return FileBaselineComparisonResult{}, err
	}
	if strings.TrimSpace(input.AppSlug) == "" {
		return FileBaselineComparisonResult{}, errors.New("app slug is required")
	}

	environment, err := h.resolveEnvironmentPath(ctx, input.OrganizationSlug, input.ProjectSlug, input.EnvironmentSlug)
	if err != nil {
		return FileBaselineComparisonResult{}, err
	}
	app, err := h.resolveAppPath(ctx, input.OrganizationSlug, input.ProjectSlug, input.EnvironmentSlug, input.AppSlug)
	if err != nil {
		return FileBaselineComparisonResult{}, err
	}

	observations, err := h.ingest.ListFileStateObservations(ctx, environment.ID, app.ID, input.Since, input.Limit)
	if err != nil {
		return FileBaselineComparisonResult{}, err
	}

	latest := map[string]map[string]domain.FileStateObservation{}
	observedHosts := map[string]struct{}{}
	for _, observation := range observations {
		if strings.TrimSpace(observation.RelativePath) == "" || strings.TrimSpace(observation.HostSlug) == "" {
			continue
		}
		observedHosts[observation.HostSlug] = struct{}{}
		byHost := latest[observation.RelativePath]
		if byHost == nil {
			byHost = map[string]domain.FileStateObservation{}
			latest[observation.RelativePath] = byHost
		}
		if _, ok := byHost[observation.HostSlug]; !ok {
			byHost[observation.HostSlug] = observation
		}
	}

	result := FileBaselineComparisonResult{
		Environment: environment,
		App:         app,
		Since:       input.Since,
	}
	for host := range observedHosts {
		result.ObservedHosts = append(result.ObservedHosts, host)
	}
	slices.Sort(result.ObservedHosts)

	for relativePath, byHost := range latest {
		difference, ok := buildFileBaselineDifference(relativePath, byHost, len(result.ObservedHosts))
		if ok {
			result.Differences = append(result.Differences, difference)
		}
	}
	slices.SortFunc(result.Differences, func(a FileBaselineDifference, b FileBaselineDifference) int {
		if severityRank(a.Severity) != severityRank(b.Severity) {
			return severityRank(b.Severity) - severityRank(a.Severity)
		}
		return strings.Compare(a.RelativePath, b.RelativePath)
	})
	return result, nil
}

func buildFileBaselineDifference(relativePath string, byHost map[string]domain.FileStateObservation, observedHostCount int) (FileBaselineDifference, bool) {
	signatures := map[string]struct{}{}
	var states []FileBaselineHostState
	for _, observation := range byHost {
		signatures[fileStateSignature(observation)] = struct{}{}
		states = append(states, FileBaselineHostState{
			HostSlug:       observation.HostSlug,
			Hostname:       observation.Hostname,
			AgentID:        observation.AgentExternalID,
			EventType:      observation.EventType,
			EventTime:      observation.EventTime,
			Path:           observation.Path,
			SHA256:         observation.SHA256,
			PreviousSHA256: observation.PreviousSHA256,
			SizeBytes:      observation.SizeBytes,
			HashSkipped:    observation.HashSkipped,
			Deleted:        observation.Deleted,
			Severity:       observation.Severity,
		})
	}
	slices.SortFunc(states, func(a FileBaselineHostState, b FileBaselineHostState) int {
		return strings.Compare(a.HostSlug, b.HostSlug)
	})

	reason := ""
	switch {
	case len(signatures) > 1:
		reason = "file state differs across reporting hosts"
	case observedHostCount > 1 && len(byHost) == 1:
		reason = "file change observed on one reporting host only"
	default:
		return FileBaselineDifference{}, false
	}

	severity := maxFileBaselineSeverity(states)
	if len(signatures) > 1 && severityRank(severity) < severityRank(domain.SeverityMedium) {
		severity = domain.SeverityMedium
	}
	return FileBaselineDifference{
		RelativePath: relativePath,
		Reason:       reason,
		Severity:     severity,
		Hosts:        states,
	}, true
}

func fileStateSignature(observation domain.FileStateObservation) string {
	if observation.Deleted {
		return "deleted"
	}
	if observation.HashSkipped {
		return fmt.Sprintf("hash-skipped:%d", observation.SizeBytes)
	}
	if observation.SHA256 != "" {
		return "sha256:" + observation.SHA256
	}
	return fmt.Sprintf("size:%d", observation.SizeBytes)
}

func maxFileBaselineSeverity(states []FileBaselineHostState) domain.Severity {
	max := domain.SeverityInfo
	for _, state := range states {
		if severityRank(state.Severity) > severityRank(max) {
			max = state.Severity
		}
	}
	return max
}

func severityRank(severity domain.Severity) int {
	switch severity {
	case domain.SeverityCritical:
		return 5
	case domain.SeverityHigh:
		return 4
	case domain.SeverityMedium:
		return 3
	case domain.SeverityLow:
		return 2
	default:
		return 1
	}
}
