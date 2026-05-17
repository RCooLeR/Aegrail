package laravel

import "github.com/rcooler/aegrail/agent/internal/modules"

const ID = "laravel"

func Spec() modules.Spec {
	return modules.Spec{
		ID:       ID,
		Name:     "Laravel",
		Priority: 50,
		Targets: []string{
			"laravel",
			"laravel spatie permission",
			"laravel horizon telescope",
		},
		Capabilities: []modules.Capability{
			modules.CapabilityLogNormalization,
			modules.CapabilitySnapshotImport,
			modules.CapabilityBaselineDiff,
			modules.CapabilityRulePack,
			modules.CapabilityReportFragments,
		},
		Notes: []string{
			"Targets the monitored Laravel layout with app/routes/config/database/resources and selected public entrypoints.",
			"Tracks users, active flags, Spatie roles and permissions, migrations, sessions, and reset tokens without collecting passwords, remember tokens, API keys, or raw secrets.",
		},
	}
}
