package modules

import (
	"fmt"
	"sort"
)

type Capability string

const (
	CapabilityLogNormalization Capability = "log_normalization"
	CapabilitySnapshotImport   Capability = "snapshot_import"
	CapabilityBaselineDiff     Capability = "baseline_diff"
	CapabilityRulePack         Capability = "rule_pack"
	CapabilityReportFragments  Capability = "report_fragments"
)

type Spec struct {
	ID           string
	Name         string
	Priority     int
	Targets      []string
	Capabilities []Capability
	Notes        []string
}

type Registry struct {
	specs map[string]Spec
}

func NewRegistry() *Registry {
	return &Registry{specs: make(map[string]Spec)}
}

func (r *Registry) Register(spec Spec) error {
	if spec.ID == "" {
		return fmt.Errorf("module ID is required")
	}
	if spec.Name == "" {
		return fmt.Errorf("module name is required")
	}
	if _, exists := r.specs[spec.ID]; exists {
		return fmt.Errorf("module %q already registered", spec.ID)
	}
	r.specs[spec.ID] = spec
	return nil
}

func (r *Registry) All() []Spec {
	specs := make([]Spec, 0, len(r.specs))
	for _, spec := range r.specs {
		specs = append(specs, spec)
	}
	sort.Slice(specs, func(i, j int) bool {
		if specs[i].Priority == specs[j].Priority {
			return specs[i].ID < specs[j].ID
		}
		return specs[i].Priority < specs[j].Priority
	})
	return specs
}

func (r *Registry) Find(id string) (Spec, bool) {
	spec, ok := r.specs[id]
	return spec, ok
}
