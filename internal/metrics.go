package trivy

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	// MetricsNamespace is the namespace for all metrics. This name is
	// prepended to all metrics.
	MetricsNamespace = "trivy_extractor"
)

type MetricService interface {
	Metrics() ([]string, error)
}

type MetricsServicer struct {
}

func (m *MetricsServicer) Metrics() ([]string, error) {
	requestURL := fmt.Sprintf("http://trivy-operator.trivy-operator:%d/metrics", 8080)
	req, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return []string{}, err
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return []string{}, err
	}

	resBody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return []string{}, err
	}
	return strings.Split(string(resBody), "\n"), nil
}

var Labels []string = []string{
	"container_name",
	"image_digest",
	"image_registry",
	"image_repository",
	"image_tag",
	"name",
	"namespace",
	"resource_kind",
	"resource_name",
	"severity",
}

type VulnMetrics struct {
	Labels []string
	Value  float64
}

var valueRegex *regexp.Regexp = regexp.MustCompile(`} (?P<value>\d+)`)

func ParseMetrics(line string, nsTeam map[string]string) (VulnMetrics, error) {
	myLabels := []string{}
	team := ""

	if !strings.HasPrefix(line, "trivy_image_vulnerabilities") {
		return VulnMetrics{}, nil
	}

	for _, l := range Labels {
		re := regexp.MustCompile(l + `="(?P<value>.*?)"`)
		entryMatches := re.FindStringSubmatch(line)
		if entryMatches == nil {
			myLabels = append(myLabels, "")
		} else {
			myLabels = append(myLabels, entryMatches[1])
		}

		if l == "namespace" {
			t, ok := nsTeam[entryMatches[1]]
			if !ok {
				team = "Unknown"
			} else {
				team = t
			}
		}
		line = strings.Replace(line, l, "", 1)
	}

	myLabels = append(myLabels, team)

	entryMatches := valueRegex.FindStringSubmatch(line)
	var result float64
	if entryMatches == nil {
		return VulnMetrics{}, nil
	}
	result, err := strconv.ParseFloat(entryMatches[1], 64)
	if err != nil {
		return VulnMetrics{}, err
	}

	return VulnMetrics{myLabels, result}, nil
}

func Report(ms MetricService, pp PrometheusMetricsService, ctx context.Context, tickerTime time.Duration, nsTeam map[string]string) error {
	ticker := time.NewTicker(tickerTime)
	for {
		select {
		case <-ticker.C:
			lines, err := ms.Metrics()
			if err != nil {
				log.Printf("error calling metrics. %s\n", err)
				return err
			}

			log.Printf("trivy.Report: received %d lines of metrics", len(lines))
			for _, l := range lines {
				vm, err := ParseMetrics(l, nsTeam)

				if err != nil {
					return err
				}

				if len(vm.Labels) > 0 {
					pp.SetTeamNamespaceVulns(vm)
				}
			}

		case <-ctx.Done():
			ticker.Stop()
			return nil
		}
	}
}

type PrometheusMetricsService interface {
	SetTeamNamespaceVulns(VulnMetrics)
}

// PrometheusMetricsServicer is a metrics provider that uses Prometheus.
type PrometheusMetricsServicer struct {
	teamNamespaceVulns *prometheus.GaugeVec
}

// NewPrometheusMetricsService returns a new PrometheusMetricsProvider.
func NewPrometheusMetricsService() PrometheusMetricsService {
	return NewPrometheusMetricsServiceForRegisterer(prometheus.DefaultRegisterer)
}

func NewPrometheusMetricsServiceForRegisterer(r prometheus.Registerer) PrometheusMetricsService {
	p := &PrometheusMetricsServicer{
		teamNamespaceVulns: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name:      "team_namespace_vulns",
				Namespace: MetricsNamespace,
				Help:      "Adds vulns metrics grouped by team and namespace",
			},
			append(Labels, "team"),
		),
	}

	// This is variadic function so we can pass as many metrics as we want
	r.MustRegister(p.teamNamespaceVulns)
	return p
}

func (p *PrometheusMetricsServicer) SetTeamNamespaceVulns(vm VulnMetrics) {
	p.teamNamespaceVulns.WithLabelValues(vm.Labels...).Set(vm.Value)
}
