package trivy

import (
	"fmt"
	"io/ioutil"
	"strings"
)

func NewNamespaceTeam(f string) map[string]string {
	m := make(map[string]string)

	b, err := ioutil.ReadFile(f)
	if err != nil {
		fmt.Println("couldnt find namespaces file. using empty namespaces")
		return m
	}

	for _, l := range strings.Split(string(b[:]), "\n") {
		s := strings.Split(l, ",")
		if len(s) != 2 {
			continue
		}
		team := s[0]
		ns := s[1]
		m[ns] = team
	}

	return m
}
