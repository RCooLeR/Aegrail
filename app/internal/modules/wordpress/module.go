package wordpress

import "github.com/rcooler/aegrail/internal/modules"

const ID = "wordpress"

func Spec() modules.Spec {
	return modules.Spec{
		ID:       ID,
		Name:     "WordPress",
		Priority: 20,
		Targets: []string{
			"wordpress",
			"woocommerce",
			"wp-admin",
			"wp-content",
		},
		Capabilities: []modules.Capability{
			modules.CapabilityLogNormalization,
			modules.CapabilitySnapshotImport,
			modules.CapabilityBaselineDiff,
			modules.CapabilityRulePack,
			modules.CapabilityReportFragments,
		},
		Notes: []string{
			"High priority target for plugin/theme drift, rogue admins, injected options, and WooCommerce data exposure.",
			"Initial snapshots should cover users, usermeta capabilities, options, active plugins, themes, cron, posts with scripts, and file inventory.",
		},
	}
}
