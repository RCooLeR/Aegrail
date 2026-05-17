package mautic

import "github.com/rcooler/aegrail/agent/internal/modules"

const ID = "mautic"

func Spec() modules.Spec {
	return modules.Spec{
		ID:       ID,
		Name:     "Mautic",
		Priority: 30,
		Targets: []string{
			"mautic",
			"mautic marketing automation",
			"mautic crm",
		},
		Capabilities: []modules.Capability{
			modules.CapabilityLogNormalization,
			modules.CapabilitySnapshotImport,
			modules.CapabilityBaselineDiff,
			modules.CapabilityRulePack,
			modules.CapabilityReportFragments,
		},
		Notes: []string{
			"Tracks user and role drift, plugin and integration changes, OAuth clients, webhooks, and high-signal file changes.",
			"Access logs are filtered to avoid routine email redirect and tracking noise while keeping admin, API, auth, and error traffic.",
		},
	}
}
