package yii2rbac

import "github.com/rcooler/aegrail/agent/internal/modules"

const ID = "yii2-rbac"

func Spec() modules.Spec {
	return modules.Spec{
		ID:       ID,
		Name:     "Yii2 RBAC",
		Priority: 40,
		Targets: []string{
			"yii2-rbac",
			"yii2 rbac",
			"yii2 postgres rbac",
		},
		Capabilities: []modules.Capability{
			modules.CapabilityLogNormalization,
			modules.CapabilitySnapshotImport,
			modules.CapabilityBaselineDiff,
			modules.CapabilityRulePack,
			modules.CapabilityReportFragments,
		},
		Notes: []string{
			"Targets RBAC-enabled Yii2 layouts with root config/controllers/models/components/migrations and selected web entrypoints.",
			"Tracks users, roles, Yii migrations, and optional Yii RBAC tables without collecting password hashes, auth keys, tokens, or raw secrets.",
		},
	}
}
