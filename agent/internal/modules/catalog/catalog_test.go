package catalog

import "testing"

func TestDefaultRegistryIncludesPriorityTargets(t *testing.T) {
	registry, err := DefaultRegistry()
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := registry.Find("prestashop"); !ok {
		t.Fatal("prestashop module is not registered")
	}
	if _, ok := registry.Find("wordpress"); !ok {
		t.Fatal("wordpress module is not registered")
	}
	if _, ok := registry.Find("mautic"); !ok {
		t.Fatal("mautic module is not registered")
	}
	if _, ok := registry.Find("yii2-rbac"); !ok {
		t.Fatal("yii2-rbac module is not registered")
	}
	if _, ok := registry.Find("laravel"); !ok {
		t.Fatal("laravel module is not registered")
	}
}
