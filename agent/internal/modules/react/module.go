package react

import "github.com/rcooler/aegrail/agent/internal/modules"

const ID = "react"

func Spec() modules.Spec {
	return modules.Spec{
		ID:       ID,
		Name:     "React",
		Priority: 70,
		Targets: []string{
			"react",
			"vite react",
			"next react frontend",
		},
		Capabilities: []modules.Capability{
			modules.CapabilityLogNormalization,
			modules.CapabilityBaselineDiff,
			modules.CapabilityRulePack,
			modules.CapabilityReportFragments,
		},
		Notes: []string{
			"Tracks package locks, build config, source, public entrypoints, service workers, access logs, and browser-visible script changes.",
			"Skips dependency installs and generated asset churn by default; use explicit extra paths for deployment manifests or reverse-proxy config.",
		},
	}
}
