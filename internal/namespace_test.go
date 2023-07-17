package trivy_test

import (
	"testing"

	trivy "github.com/metal-toolbox/trivy-extractor/internal"
)

func TestNamespace(t *testing.T) {
	m := trivy.NewNamespaceTeam("../data/namespaces.csv")

	tm, ok := m["app-1"]
	if !ok {
		t.Fatalf("app-1 not found")
	}

	if tm != "TEAM 1" {
		t.Fatalf("%s is not TEAM 1", tm)
	}

}
