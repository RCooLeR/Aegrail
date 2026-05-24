package static

import "github.com/rcooler/aegrail/agent/internal/modules"

const ID = "static"

func Spec() modules.Spec {
	return modules.Spec{
		ID:       ID,
		Name:     "Static site",
		Priority: 60,
		Targets: []string{
			"static html",
			"deployed frontend assets",
			"nginx apache static site",
		},
		Capabilities: []modules.Capability{
			modules.CapabilityLogNormalization,
			modules.CapabilityBaselineDiff,
			modules.CapabilityRulePack,
			modules.CapabilityReportFragments,
		},
		Notes: []string{
			"Tracks static entrypoints, service workers, manifests, high-signal file drift, access logs, and browser-visible script changes.",
			"Does not define a database snapshot profile; static sites should normally rely on file, log, browser, and coverage collectors.",
		},
	}
}
