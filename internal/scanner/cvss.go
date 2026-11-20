package scanner

import (
	"math"
	"strings"
)

// CVSSBaseScore computes the base score of a CVSS v3.0/v3.1 or v2 vector.
// ok is false for unsupported versions (v4.0 needs the official lookup tables
// and is shown as a vector only) or malformed vectors.
func CVSSBaseScore(vector string) (score float64, version string, ok bool) {
	switch {
	case strings.HasPrefix(vector, "CVSS:3.1/"), strings.HasPrefix(vector, "CVSS:3.0/"):
		s, ok := cvss3(vector)
		return s, vector[5:8], ok
	case strings.HasPrefix(vector, "CVSS:4.0/"):
		return 0, "4.0", false
	case strings.HasPrefix(vector, "AV:") && strings.Contains(vector, "Au:"):
		s, ok := cvss2(vector)
		return s, "2.0", ok
	}
	return 0, "", false
}

func parseMetrics(vector string) map[string]string {
	m := map[string]string{}
	for _, part := range strings.Split(vector, "/") {
		k, v, ok := strings.Cut(part, ":")
		if ok {
			m[k] = v
		}
	}
	return m
}

func cvss3(vector string) (float64, bool) {
	m := parseMetrics(vector)
	av := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
	ac := map[string]float64{"L": 0.77, "H": 0.44}
	ui := map[string]float64{"N": 0.85, "R": 0.62}
	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	scope := m["S"]
	if scope != "U" && scope != "C" {
		return 0, false
	}
	pr := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if scope == "C" {
		pr = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
	}
	vAV, ok1 := av[m["AV"]]
	vAC, ok2 := ac[m["AC"]]
	vPR, ok3 := pr[m["PR"]]
	vUI, ok4 := ui[m["UI"]]
	vC, ok5 := cia[m["C"]]
	vI, ok6 := cia[m["I"]]
	vA, ok7 := cia[m["A"]]
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7) {
		return 0, false
	}
	iss := 1 - (1-vC)*(1-vI)*(1-vA)
	var impact float64
	if scope == "U" {
		impact = 6.42 * iss
	} else {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	exploitability := 8.22 * vAV * vAC * vPR * vUI
	if impact <= 0 {
		return 0, true
	}
	if scope == "U" {
		return roundUp(math.Min(impact+exploitability, 10)), true
	}
	return roundUp(math.Min(1.08*(impact+exploitability), 10)), true
}

// roundUp implements the CVSS v3.1 Roundup function.
func roundUp(x float64) float64 {
	i := int64(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return float64(i/10000+1) / 10
}

func cvss2(vector string) (float64, bool) {
	m := parseMetrics(vector)
	av := map[string]float64{"L": 0.395, "A": 0.646, "N": 1.0}
	ac := map[string]float64{"H": 0.35, "M": 0.61, "L": 0.71}
	au := map[string]float64{"M": 0.45, "S": 0.56, "N": 0.704}
	cia := map[string]float64{"N": 0, "P": 0.275, "C": 0.660}
	vAV, ok1 := av[m["AV"]]
	vAC, ok2 := ac[m["AC"]]
	vAu, ok3 := au[m["Au"]]
	vC, ok4 := cia[m["C"]]
	vI, ok5 := cia[m["I"]]
	vA, ok6 := cia[m["A"]]
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6) {
		return 0, false
	}
	impact := 10.41 * (1 - (1-vC)*(1-vI)*(1-vA))
	exploitability := 20 * vAV * vAC * vAu
	f := 0.0
	if impact != 0 {
		f = 1.176
	}
	base := ((0.6 * impact) + (0.4 * exploitability) - 1.5) * f
	return math.Round(base*10) / 10, true
}
