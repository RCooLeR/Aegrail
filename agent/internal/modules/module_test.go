package modules

import "testing"

func TestRegistryOrdersByPriority(t *testing.T) {
	registry := NewRegistry()
	if err := registry.Register(Spec{ID: "later", Name: "Later", Priority: 20}); err != nil {
		t.Fatal(err)
	}
	if err := registry.Register(Spec{ID: "first", Name: "First", Priority: 10}); err != nil {
		t.Fatal(err)
	}

	specs := registry.All()
	if got := specs[0].ID; got != "first" {
		t.Fatalf("first module = %q, want first", got)
	}
}

func TestRegistryRejectsDuplicateID(t *testing.T) {
	registry := NewRegistry()
	if err := registry.Register(Spec{ID: "wordpress", Name: "WordPress"}); err != nil {
		t.Fatal(err)
	}
	if err := registry.Register(Spec{ID: "wordpress", Name: "Duplicate"}); err == nil {
		t.Fatal("expected duplicate module error")
	}
}
