package hub

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/rcooler/aegrail/hub/internal/domain"
)

type deploymentListErrorInventory struct {
	*memoryInventoryRepository
	err error
}

func (r *deploymentListErrorInventory) ListDeploymentMarkers(context.Context, domain.ID, domain.ID) ([]domain.DeploymentMarker, error) {
	return nil, r.err
}

func TestApplyDeploymentContextFailsOpenWhenMarkerLookupFails(t *testing.T) {
	markerErr := errors.New("deployment store unavailable")
	var reported error
	hub := New(Dependencies{
		Inventory: &deploymentListErrorInventory{
			memoryInventoryRepository: newMemoryInventoryRepository(),
			err:                       markerErr,
		},
		BackgroundError: func(err error) { reported = err },
	})
	finding := domain.HubFinding{
		RuleID:   "browser-script-domain-new",
		Severity: domain.SeverityHigh,
		Metadata: map[string]any{"source": "browser"},
	}

	findings, err := hub.applyDeploymentContextToFindings(context.Background(), "env-production", "app-main", []domain.HubFinding{finding})
	if err != nil {
		t.Fatalf("applyDeploymentContextToFindings returned error: %v", err)
	}
	if len(findings) != 1 || findings[0].RuleID != finding.RuleID || findings[0].Severity != finding.Severity {
		t.Fatalf("findings = %#v, want original finding preserved", findings)
	}
	if _, ok := findings[0].Metadata["deployment_context"]; ok {
		t.Fatalf("metadata = %#v, failed lookup must not invent deployment context", findings[0].Metadata)
	}
	if reported == nil || !strings.Contains(reported.Error(), markerErr.Error()) {
		t.Fatalf("reported error = %v, want marker lookup failure reported", reported)
	}
}
