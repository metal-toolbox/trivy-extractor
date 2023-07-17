package trivy

import (
	"gopkg.in/yaml.v3"
)

func NewTrivyReport(b []byte) *TrivyReport {
	var report TrivyReport
	err := yaml.Unmarshal(b, &report)
	if err != nil {
		report = TrivyReport{}
	}
	return &report
}

type TrivyReport struct {
	Metadata struct {
		Name        string `yaml:"name"`
		Annotations struct {
			TrivyOperatorAquasecurityGithubIoReportTtl string `yaml:"trivy-operator.aquasecurity.github.io/report-ttl"`
		} `yaml:"annotations"`
		CreationTimestamp string `yaml:"creationTimestamp"`
		Generation        int    `yaml:"generation"`
		Labels            struct {
			TrivyOperatorResourceNamespace string `yaml:"trivy-operator.resource.namespace"`
			ResourceSpecHash               string `yaml:"resource-spec-hash"`
			TrivyOperatorContainerName     string `yaml:"trivy-operator.container.name"`
			TrivyOperatorResourceKind      string `yaml:"trivy-operator.resource.kind"`
			TrivyOperatorResourceName      string `yaml:"trivy-operator.resource.name"`
		} `yaml:"labels"`
		Namespace       string `yaml:"namespace"`
		ResourceVersion string `yaml:"resourceVersion"`
		Uid             string `yaml:"uid"`
	} `yaml:"metadata"`
	Report struct {
		Scanner struct {
			Name    string `yaml:"name"`
			Vendor  string `yaml:"vendor"`
			Version string `yaml:"version"`
		} `yaml:"scanner"`
		Summary struct {
			CriticalCount int `yaml:"criticalCount"`
			HighCount     int `yaml:"highCount"`
			LowCount      int `yaml:"lowCount"`
			MediumCount   int `yaml:"mediumCount"`
			NoneCount     int `yaml:"noneCount"`
			UnknownCount  int `yaml:"unknownCount"`
		} `yaml:"summary"`
		UpdateTimestamp string `yaml:"updateTimestamp"`
		Vulnerabilities []struct {
			Links            []string `yaml:"links"`
			PrimaryLink      string   `yaml:"primaryLink"`
			Resource         string   `yaml:"resource"`
			Score            float64  `yaml:"score"`
			Target           string   `yaml:"target"`
			VulnerabilityID  string   `yaml:"vulnerabilityID"`
			FixedVersion     string   `yaml:"fixedVersion"`
			InstalledVersion string   `yaml:"installedVersion"`
			Severity         string   `yaml:"severity"`
			Title            string   `yaml:"title"`
		} `yaml:"vulnerabilities"`
		Artifact struct {
			Repository string `yaml:"repository"`
			Tag        string `yaml:"tag"`
		} `yaml:"artifact"`
		Registry struct {
			Server string `yaml:"server"`
		} `yaml:"registry"`
	} `yaml:"report"`
}
