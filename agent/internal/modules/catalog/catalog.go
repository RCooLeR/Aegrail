package catalog

import (
	"github.com/rcooler/aegrail/agent/internal/modules"
	"github.com/rcooler/aegrail/agent/internal/modules/laravel"
	"github.com/rcooler/aegrail/agent/internal/modules/mautic"
	"github.com/rcooler/aegrail/agent/internal/modules/prestashop"
	"github.com/rcooler/aegrail/agent/internal/modules/wordpress"
	"github.com/rcooler/aegrail/agent/internal/modules/yii2rbac"
)

func DefaultRegistry() (*modules.Registry, error) {
	registry := modules.NewRegistry()
	for _, spec := range []modules.Spec{
		prestashop.Spec(),
		wordpress.Spec(),
		mautic.Spec(),
		yii2rbac.Spec(),
		laravel.Spec(),
	} {
		if err := registry.Register(spec); err != nil {
			return nil, err
		}
	}
	return registry, nil
}
