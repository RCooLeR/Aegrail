package nodejs

import "github.com/rcooler/aegrail/agent/internal/modules"

const ID = "nodejs"

func Spec() modules.Spec {
	return modules.Spec{
		ID:       ID,
		Name:     "Node.js",
		Priority: 80,
		Targets: []string{
			"node.js",
			"express",
			"node service",
		},
		Capabilities: []modules.Capability{
			modules.CapabilityLogNormalization,
			modules.CapabilityBaselineDiff,
			modules.CapabilityRulePack,
			modules.CapabilityReportFragments,
		},
		Notes: []string{
			"Tracks package locks, entrypoints, source, routes, middleware, config, access logs, and browser/API request signals.",
			"Does not define a generic database profile; add a supported database collector only when the application schema is explicitly known.",
		},
	}
}
