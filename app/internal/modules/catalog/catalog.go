package catalog

import (
	"github.com/rcooler/aegrail/internal/modules"
	"github.com/rcooler/aegrail/internal/modules/prestashop"
	"github.com/rcooler/aegrail/internal/modules/wordpress"
)

func DefaultRegistry() (*modules.Registry, error) {
	registry := modules.NewRegistry()
	for _, spec := range []modules.Spec{
		prestashop.Spec(),
		wordpress.Spec(),
	} {
		if err := registry.Register(spec); err != nil {
			return nil, err
		}
	}
	return registry, nil
}
