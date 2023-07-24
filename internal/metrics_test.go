package trivy_test

import (
	"context"
	_ "embed"
	"path/filepath"
	"strings"
	"testing"
	"time"

	trivy "github.com/metal-toolbox/trivy-extractor/internal"
)

type FakeMetricsServicer struct {
}

//go:embed test_data/metrics.txt
var FakeMetricsData string

func (f *FakeMetricsServicer) Metrics() ([]string, error) {
	return strings.Split(FakeMetricsData, "\n"), nil
}

func TestFakeMetrics(t *testing.T) {
	fm := FakeMetricsServicer{}
	m, _ := fm.Metrics()

	if len(m) != 7 {
		t.Fatalf("there should be %d metrics lines, there is only %d", 7, len(m))
	}
}

func TestParseMetric(t *testing.T) {
	nsTeam := trivy.NewNamespaceTeam("../data/namespaces.csv")
	vm, _ := trivy.ParseMetrics(strings.Split(FakeMetricsData, "\n")[0], nsTeam)

	if len(vm.Labels) != len(trivy.Labels)+1 {
		t.Fatalf("should have equal label lengths. actual %d, expected %d", len(vm.Labels), len(trivy.Labels))
	}

	expected := []string{
		"app",
		"",
		"ghcr.io",
		"app/app",
		"v1",
		"replicaset-app-1-app",
		"app-1",
		"ReplicaSet",
		"app-1",
		"Critical",
		"TEAM 1",
	}

	for i := range vm.Labels {
		t.Logf(vm.Labels[i])
		if vm.Labels[i] != expected[i] {
			t.Fatalf("labels are not correct. actual %s Expected %s ", vm.Labels, expected)
		}
	}
	var expectedResult float64 = 1
	if float64(expectedResult) != vm.Value {
		t.Fatalf("Result incorrect, actual %f, expected %f", vm.Value, expectedResult)
	}
}

type FakePromServicer struct {
	Calls []trivy.VulnMetrics
}

func (p *FakePromServicer) SetTeamNamespaceVulns(vm trivy.VulnMetrics) {
	p.Calls = append(p.Calls, vm)
}

func TestReport(t *testing.T) {
	p, _ := filepath.Abs("../data/namespaces.csv")

	nsTeam := trivy.NewNamespaceTeam(p)
	fm := &FakeMetricsServicer{}
	ps := &FakePromServicer{}

	ctx, can := context.WithCancel(context.Background())
	go (func() {
		trivy.Report(fm, ps, ctx, 10*time.Millisecond, nsTeam)
	})()

	time.Sleep(15 * time.Millisecond)
	can()
	if len(ps.Calls) != 5 {
		t.Fatalf("should have processed 5 but processed only %d", len(ps.Calls))
	}
}
