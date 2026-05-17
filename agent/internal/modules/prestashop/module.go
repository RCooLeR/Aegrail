package prestashop

import "github.com/rcooler/aegrail/agent/internal/modules"

const ID = "prestashop"

func Spec() modules.Spec {
	return modules.Spec{
		ID:       ID,
		Name:     "PrestaShop",
		Priority: 10,
		Targets: []string{
			"prestashop",
			"classic prestashop back office",
			"prestashop ecommerce",
		},
		Capabilities: []modules.Capability{
			modules.CapabilityLogNormalization,
			modules.CapabilitySnapshotImport,
			modules.CapabilityBaselineDiff,
			modules.CapabilityRulePack,
			modules.CapabilityReportFragments,
		},
		Notes: []string{
			"High priority target for ecommerce compromise and customer export detection.",
			"Initial snapshots should cover employees, sessions, logs, configuration, modules, hooks, tabs, and access.",
		},
	}
}
