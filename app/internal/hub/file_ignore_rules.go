package hub

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/rcooler/aegrail/internal/domain"
)

type IgnoreFilePathFromFindingInput struct {
	OrganizationSlug string
	ProjectSlug      string
	EnvironmentSlug  string
	AppSlug          string
	FindingID        string
	Path             string
	Reason           string
	Actor            string
}

type IgnoreFilePathFromFindingResult struct {
	Finding           domain.HubFinding
	Rule              domain.HubFileIgnoreRule
	AgentExcludeHint  string
	NormalizedPattern string
}

func (h *Hub) IgnoreFilePathFromFinding(ctx context.Context, input IgnoreFilePathFromFindingInput) (IgnoreFilePathFromFindingResult, error) {
	if h.findings == nil {
		return IgnoreFilePathFromFindingResult{}, errors.New("finding repository is not configured")
	}
	if h.fileIgnoreRules == nil {
		return IgnoreFilePathFromFindingResult{}, errors.New("file ignore rule repository is not configured")
	}
	if err := h.requireInventory(); err != nil {
		return IgnoreFilePathFromFindingResult{}, err
	}

	org, project, environment, err := h.resolveEnvironmentContext(ctx, input.OrganizationSlug, input.ProjectSlug, input.EnvironmentSlug)
	if err != nil {
		return IgnoreFilePathFromFindingResult{}, err
	}
	var appID domain.ID
	if strings.TrimSpace(input.AppSlug) != "" {
		app, err := h.resolveAppPath(ctx, input.OrganizationSlug, input.ProjectSlug, input.EnvironmentSlug, input.AppSlug)
		if err != nil {
			return IgnoreFilePathFromFindingResult{}, err
		}
		appID = app.ID
	}

	findingID := domain.ID(strings.TrimSpace(input.FindingID))
	if findingID == "" {
		return IgnoreFilePathFromFindingResult{}, errors.New("finding id is required")
	}
	finding, err := h.findings.GetHubFinding(ctx, findingID, environment.ID, appID)
	if err != nil {
		return IgnoreFilePathFromFindingResult{}, err
	}

	rawPath := strings.TrimSpace(input.Path)
	if rawPath == "" {
		rawPath = deriveFileIgnorePathFromFinding(finding)
	}
	normalized := normalizeFileIgnorePath(rawPath)
	if normalized == "" {
		return IgnoreFilePathFromFindingResult{}, errors.New("file ignore path is required")
	}

	actor := strings.TrimSpace(input.Actor)
	if actor == "" {
		actor = "dashboard"
	}
	reason := strings.TrimSpace(input.Reason)
	if reason == "" {
		reason = "operator_ignored_file_path"
	}

	rule, err := h.fileIgnoreRules.SaveHubFileIgnoreRule(ctx, domain.HubFileIgnoreRule{
		OrganizationID:  org.ID,
		ProjectID:       project.ID,
		EnvironmentID:   environment.ID,
		AppID:           appID,
		MatchKind:       "file_path_prefix",
		MatchValue:      normalized,
		NormalizedValue: normalized,
		Reason:          reason,
		CreatedBy:       actor,
		Status:          "active",
	})
	if err != nil {
		return IgnoreFilePathFromFindingResult{}, err
	}

	note := fmt.Sprintf("Ignored future file findings under %s. Agent-side scanning still runs unless this path is also added to files.exclude.", normalized)
	updated, err := h.findings.UpdateHubFindingStatus(ctx, finding.ID, environment.ID, domain.HubFindingStatusUpdate{
		Status: "false_positive",
		Reason: "file_path_ignored",
		Note:   note,
		Actor:  actor,
	})
	if err != nil {
		return IgnoreFilePathFromFindingResult{}, err
	}

	return IgnoreFilePathFromFindingResult{
		Finding:           updated,
		Rule:              rule,
		AgentExcludeHint:  normalized,
		NormalizedPattern: normalized,
	}, nil
}

func deriveFileIgnorePathFromFinding(finding domain.HubFinding) string {
	if values, ok := finding.Metadata["files"].([]any); ok {
		files := make([]string, 0, len(values))
		for _, value := range values {
			if text, ok := value.(string); ok && strings.TrimSpace(text) != "" {
				files = append(files, text)
			}
		}
		if common := commonFileParent(files); common != "" {
			return common
		}
	}
	if values, ok := finding.Metadata["files"].([]string); ok {
		if common := commonFileParent(values); common != "" {
			return common
		}
	}
	if events, ok := finding.Metadata["events"].([]any); ok {
		for _, item := range events {
			event, ok := item.(map[string]any)
			if !ok {
				continue
			}
			eventType, _ := event["type"].(string)
			if !strings.HasPrefix(eventType, "file.") {
				continue
			}
			if target, ok := event["target"].(string); ok && strings.TrimSpace(target) != "" {
				return parentFilePath(target)
			}
		}
	}
	if root, ok := finding.Metadata["file_group_root"].(string); ok {
		return root
	}
	return ""
}

func commonFileParent(files []string) string {
	var parts []string
	for _, file := range files {
		parent := parentFilePath(file)
		if parent == "" {
			continue
		}
		current := strings.Split(normalizeFileIgnorePath(parent), "/")
		if len(parts) == 0 {
			parts = current
			continue
		}
		limit := min(len(parts), len(current))
		index := 0
		for index < limit && parts[index] == current[index] {
			index++
		}
		parts = parts[:index]
	}
	return strings.Join(parts, "/")
}

func parentFilePath(value string) string {
	normalized := normalizeFileIgnorePath(value)
	if normalized == "" {
		return ""
	}
	parent := path.Dir(normalized)
	if parent == "." || parent == "/" {
		return normalized
	}
	return parent
}

func normalizeFileIgnorePath(value string) string {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\\", "/"))
	for strings.Contains(value, "//") {
		value = strings.ReplaceAll(value, "//", "/")
	}
	value = strings.TrimPrefix(value, "./")
	value = strings.Trim(value, "/")
	return strings.ToLower(value)
}
