package policy

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/grype"
)

// pocPattern marks links to public exploits or proof-of-concept code: the pattern from the design
// spec, section 4.2 (docs/superpowers/specs/2026-09-25-policy-mode-design.md).
var pocPattern = regexp.MustCompile(`(?i)exploit-db\.com|packetstormsecurity\.com/files|rapid7\.com/db/modules|metasploit|0day\.today|seebug\.org|github\.com/[^/]+/[^/]*(poc|exploit|cve-\d{4}-\d+)`)

// networkVector matches the base attack vector "network" in CVSS v2, v3 and v4 vectors,
// but not the environmental MAV:N.
var networkVector = regexp.MustCompile(`(^|/)AV:N(/|$)`)

// facts are what the rules look at, collected from one grype match.
type facts struct {
	vuln     grype.Vulnerability
	cves     []string
	exploits []string // Exploit-DB ids
	poc      string   // first link to a proof of concept
	network  bool     // some CVSS vector has AV:N
	vectors  bool     // there is at least one CVSS vector
}

func collectFacts(m grype.Match, lookup ExploitLookup) facts {
	f := facts{vuln: m.Vulnerability, cves: cveIDs(m), poc: firstPoC(m), network: networkReachable(m), vectors: hasVector(m)}
	if lookup != nil {
		f.exploits = exploitIDs(f.cves, lookup)
	}
	return f
}

func (f facts) hasExploit() bool {
	return len(f.exploits) > 0 || f.poc != ""
}

// malwarePrefixes are the openings of GitHub advisories about malicious packages. "Malicious code in"
// marks packages from OpenSSF malicious-packages that GitHub imported. "Embedded malware in" (lower
// case "malware", unlike "Embedded Malicious Code in") marks the 2021 npm hijacks of ua-parser-js,
// coa and rc.
var malwarePrefixes = []string{
	"Malware in ", "Malicious code in ", "Malicious Package in ", "Embedded Malicious Code in ", "Embedded malware in ",
}

// malware reports whether the finding is a malicious package rather than a flaw: GitHub publishes
// such advisories with one of the fixed openings in malwarePrefixes, or — for crates pulled from
// crates.io — with RustSec's "removed from crates.io ... malicious code" wording; for the rest,
// knownMalwareAdvisories lists, by the vulnerability id grype reports, the GitHub advisories whose
// titles follow neither, but only for GitHub advisory findings (Namespace "github:..."): grype keys
// a distro finding by the CVE id itself, and that id can collide with an unrelated map entry. CWE-506
// is embedded malicious code.
func (f facts) malware() (bool, string) {
	for _, p := range malwarePrefixes {
		if strings.HasPrefix(f.vuln.Description, p) {
			return true, "github"
		}
	}
	if strings.Contains(f.vuln.Description, "removed from crates.io") && strings.Contains(f.vuln.Description, "malicious code") {
		return true, "github"
	}
	if strings.HasPrefix(f.vuln.Namespace, "github:") && knownMalwareAdvisories[f.vuln.ID] {
		return true, "github"
	}
	for _, c := range f.vuln.CWEs {
		if c.CWE == "CWE-506" {
			return true, "cwe"
		}
	}
	return false, ""
}

// cveIDs lists the CVEs of a finding: its own id, related records, and the CVEs grype attached
// EPSS, KEV and CWE data for. Advisories such as ALAS or ELSA reach their CVEs this way.
func cveIDs(m grype.Match) []string {
	var out []string
	seen := map[string]bool{}
	add := func(id string) {
		id = strings.ToUpper(strings.TrimSpace(id))
		if strings.HasPrefix(id, "CVE-") && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	add(m.Vulnerability.ID)
	for _, r := range m.RelatedVulnerabilities {
		add(r.ID)
	}
	for _, e := range m.Vulnerability.EPSS {
		add(e.CVE)
	}
	for _, k := range m.Vulnerability.KnownExploited {
		add(k.CVE)
	}
	for _, c := range m.Vulnerability.CWEs {
		add(c.CVE)
	}
	return out
}

// exploitIDs merges the Exploit-DB ids of every CVE in cves into one sorted, de-duplicated list.
// It does not modify the slices lookup.Lookup returns.
func exploitIDs(cves []string, lookup ExploitLookup) []string {
	var out []string
	seen := map[string]bool{}
	for _, cve := range cves {
		for _, id := range lookup.Lookup(cve) {
			if !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	sort.Slice(out, func(a, b int) bool {
		x, errX := strconv.Atoi(out[a])
		y, errY := strconv.Atoi(out[b])
		if errX != nil || errY != nil {
			return out[a] < out[b]
		}
		return x < y
	})
	return out
}

// firstPoC returns the first link matching pocPattern, checking the vulnerability's own URLs
// before those of related records.
func firstPoC(m grype.Match) string {
	for _, u := range m.Vulnerability.URLs {
		if pocPattern.MatchString(u) {
			return u
		}
	}
	for _, r := range m.RelatedVulnerabilities {
		for _, u := range r.URLs {
			if pocPattern.MatchString(u) {
				return u
			}
		}
	}
	return ""
}

func networkReachable(m grype.Match) bool {
	for _, c := range allCvss(m) {
		if networkVector.MatchString(c.Vector) {
			return true
		}
	}
	return false
}

func hasVector(m grype.Match) bool {
	for _, c := range allCvss(m) {
		if c.Vector != "" {
			return true
		}
	}
	return false
}

func allCvss(m grype.Match) []grype.Cvss {
	out := append([]grype.Cvss(nil), m.Vulnerability.Cvss...)
	for _, r := range m.RelatedVulnerabilities {
		out = append(out, r.Cvss...)
	}
	return out
}
