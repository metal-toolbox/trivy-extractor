package trivy

import (
	"fmt"
	"io/ioutil"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

func Alert() error {
	ns := NewNamespaceTeam("../data/namespaces.csv")
	fis, err := ioutil.ReadDir("reports")
	if err != nil {
		return fmt.Errorf("cannot read reports dir")
	}
	for _, fi := range fis {
		if fi.IsDir() {
			continue
		}

		p, _ := filepath.Abs("reports")
		b, err := ioutil.ReadFile(filepath.Join(p, fi.Name()))
		if err != nil {
			return fmt.Errorf("cannot read file %s", fi.Name())
		}

		r := NewTrivyReport(b)
		team := ns[r.Metadata.Namespace]
		fmt.Printf("Simulate alerting teams channel %s\n", team)
		fmt.Printf("Namespace: %s  \n", r.Metadata.Namespace)

		yml, _ := yaml.Marshal(r.Report)
		fmt.Printf("Report: %s  \n", yml)
	}
	return nil
}
