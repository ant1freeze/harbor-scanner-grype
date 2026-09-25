package policy

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/harbor"
)

// reason is the explanation put in front of the vulnerability description in Harbor:
// "<level>: <main reason>; <fact>; <fact>." Harbor shows it as one paragraph.
type reason struct {
	level harbor.Severity
	main  string
	facts []string
}

func (r reason) String() string {
	s := r.level.String() + ": " + r.main
	for _, f := range r.facts {
		s += "; " + f
	}
	return s + "."
}

// formatPercent renders an EPSS probability (0–1) as a percentage: 0.92 → "92%", 0.524 → "52.4%".
func formatPercent(p float64) string {
	v := p * 100
	if v > 0 && v < 0.05 {
		return "<0.1%"
	}
	return strings.TrimSuffix(strconv.FormatFloat(v, 'f', 1, 64), ".0") + "%"
}

// formatRisk renders a grype risk (0–100) the way grype prints it: one decimal, "<0.1" for tiny values.
func formatRisk(r float64) string {
	if r > 0 && r < 0.05 {
		return "<0.1"
	}
	return strconv.FormatFloat(r, 'f', 1, 64)
}

func formatThreshold(v float64) string {
	return strconv.FormatFloat(v, 'f', -1, 64)
}

// exploitFact names the exploits of a finding: Exploit-DB ids first, at most three, else the PoC link.
func exploitFact(f facts) string {
	switch {
	case len(f.exploits) > 0:
		return "есть эксплойт в Exploit-DB (" + listIDs(f.exploits, 3) + ")"
	case f.poc != "":
		return "есть PoC (" + shortURL(f.poc) + ")"
	default:
		return "эксплойтов не найдено"
	}
}

func listIDs(ids []string, max int) string {
	if len(ids) <= max {
		return strings.Join(ids, ", ")
	}
	return strings.Join(ids[:max], ", ") + fmt.Sprintf(" и ещё %d", len(ids)-max)
}

// shortURL drops the scheme and "www." and caps the length at most 80 characters, cutting only
// on a rune boundary so the result is always valid UTF-8.
func shortURL(u string) string {
	u = strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	u = strings.TrimPrefix(u, "www.")
	if runes := []rune(u); len(runes) > 80 {
		u = string(runes[:77]) + "..."
	}
	return u
}
