package hub

import (
	"context"
	"errors"
	"testing"

	"github.com/rcooler/aegrail/hub/internal/wire"
)

func TestSaveAgentDoesNotReplaceProvisionedWireKey(t *testing.T) {
	hub := New(Dependencies{Inventory: newMemoryInventoryRepository()})
	ctx := context.Background()

	if _, err := hub.SaveOrganization(ctx, SaveOrganizationInput{Slug: "acme", Name: "Acme"}); err != nil {
		t.Fatalf("SaveOrganization returned error: %v", err)
	}
	if _, err := hub.SaveProject(ctx, SaveProjectInput{OrganizationSlug: "acme", Slug: "customer-site", Name: "Customer Site"}); err != nil {
		t.Fatalf("SaveProject returned error: %v", err)
	}
	if _, err := hub.SaveEnvironment(ctx, SaveEnvironmentInput{OrganizationSlug: "acme", ProjectSlug: "customer-site", Slug: "production", Name: "Production"}); err != nil {
		t.Fatalf("SaveEnvironment returned error: %v", err)
	}
	if _, err := hub.SaveHost(ctx, SaveHostInput{OrganizationSlug: "acme", ProjectSlug: "customer-site", EnvironmentSlug: "production", Slug: "web-01"}); err != nil {
		t.Fatalf("SaveHost returned error: %v", err)
	}

	_, firstPublicKey, err := wire.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair first returned error: %v", err)
	}
	_, secondPublicKey, err := wire.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair second returned error: %v", err)
	}

	if _, err := hub.SaveAgent(ctx, SaveAgentInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "customer-site",
		EnvironmentSlug:  "production",
		HostSlug:         "web-01",
		AgentID:          "agt_web_01",
		NodePublicKey:    firstPublicKey,
	}); err != nil {
		t.Fatalf("SaveAgent first returned error: %v", err)
	}

	_, err = hub.SaveAgent(ctx, SaveAgentInput{
		OrganizationSlug: "acme",
		ProjectSlug:      "customer-site",
		EnvironmentSlug:  "production",
		HostSlug:         "web-01",
		AgentID:          "agt_web_01",
		NodePublicKey:    secondPublicKey,
	})
	if !errors.Is(err, ErrAgentAlreadyProvisioned) {
		t.Fatalf("SaveAgent second error = %v, want ErrAgentAlreadyProvisioned", err)
	}
}
