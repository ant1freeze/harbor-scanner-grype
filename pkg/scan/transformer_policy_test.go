package scan

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/grype"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/harbor"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/policy"
)

type fakeExploits map[string][]string

func (f fakeExploits) Lookup(cve string) []string { return f[cve] }

var testRequest = harbor.ScanRequest{Artifact: harbor.Artifact{Repository: "library/n8n", Digest: "sha256:0123"}}

var policyThresholds = policy.Thresholds{Critical: 70, High: 30, Medium: 10}

func policyTransformer(exploits policy.ExploitLookup) Transformer {
	config := etc.RiskConfig{Risk: etc.RiskConfigData{Enabled: true, Mode: "policy"}}
	return NewTransformer(&SystemClock{}, config, policyThresholds, exploits)
}

func TestTransformOneItemPerMatch(t *testing.T) {
	vuln := grype.Vulnerability{ID: "CVE-2025-15467", Severity: "Critical", Risk: 49.3,
		EPSS: []grype.EPSS{{CVE: "CVE-2025-15467", Score: 0.524}}, Fix: grype.Fix{Versions: []string{"3.5.5-r0"}}}
	report := grype.Report{Matches: []grype.Match{
		{Vulnerability: vuln, Artifact: grype.Artifact{Name: "libcrypto3", Version: "3.5.4-r0"}},
		{Vulnerability: vuln, Artifact: grype.Artifact{Name: "libssl3", Version: "3.5.4-r0"}},
		{Vulnerability: vuln, Artifact: grype.Artifact{Name: "openssl", Version: "3.5.4-r0"}},
	}}

	result := policyTransformer(nil).Transform("application/vnd.security.vulnerability.report", testRequest, report)

	require.Len(t, result.Vulnerabilities, 3)
	var packages []string
	for _, item := range result.Vulnerabilities {
		packages = append(packages, item.Pkg)
		assert.Equal(t, "CVE-2025-15467", item.ID)
		assert.Equal(t, "3.5.4-r0", item.Version)
		assert.Equal(t, "3.5.5-r0", item.FixVersion)
		assert.Equal(t, harbor.SevHigh, item.Severity)
	}
	assert.Equal(t, []string{"libcrypto3", "libssl3", "openssl"}, packages)
}

func TestTransformPolicyModeExplainsLevel(t *testing.T) {
	report := grype.Report{Matches: []grype.Match{
		{
			Vulnerability: grype.Vulnerability{
				ID: "GHSA-83qj-6fr2-vhqg", Severity: "Critical", Risk: 98.7,
				Description:    "Apache Tomcat: Potential RCE and/or information disclosure and/or information corruption with partial PUT",
				URLs:           []string{"https://github.com/advisories/GHSA-83qj-6fr2-vhqg"},
				KnownExploited: []grype.KnownExploited{{CVE: "CVE-2025-24813", DateAdded: "2025-04-01"}},
			},
			Artifact: grype.Artifact{Name: "tomcat-embed-core", Version: "10.1.30"},
		},
		{
			Vulnerability: grype.Vulnerability{
				ID: "CVE-2023-45288", Severity: "High", Risk: 69.0,
				Description: "An attacker may cause an HTTP/2 endpoint to read arbitrary amounts of header data.",
				EPSS:        []grype.EPSS{{CVE: "CVE-2023-45288", Score: 0.92}},
			},
			Artifact: grype.Artifact{Name: "stdlib", Version: "go1.21.0"},
		},
	}}
	// appendMissing must copy vuln.URLs rather than mutate it in place.
	tomcatURLs := report.Matches[0].Vulnerability.URLs

	result := policyTransformer(fakeExploits{"CVE-2025-24813": {"52134"}}).
		Transform("application/vnd.security.vulnerability.report", testRequest, report)

	require.Len(t, result.Vulnerabilities, 2)
	tomcat, golang := result.Vulnerabilities[0], result.Vulnerabilities[1]

	assert.Equal(t, harbor.SevCritical, tomcat.Severity)
	assert.Equal(t, "Critical: есть в каталоге KEV с 2025-04-01; есть эксплойт в Exploit-DB (52134); риск grype 98.7."+
		" — Apache Tomcat: Potential RCE and/or information disclosure and/or information corruption with partial PUT", tomcat.Description)
	assert.Equal(t, []string{"https://github.com/advisories/GHSA-83qj-6fr2-vhqg", "https://www.exploit-db.com/exploits/52134"}, tomcat.Links)
	assert.Len(t, tomcatURLs, 1)

	assert.Equal(t, harbor.SevHigh, golang.Severity)
	assert.Equal(t, "High: риск grype 69.0, порог High от 30 (EPSS 92%, критичность grype High); эксплойтов не найдено; в KEV нет."+
		" — An attacker may cause an HTTP/2 endpoint to read arbitrary amounts of header data.", golang.Description)

	assert.Equal(t, harbor.SevCritical, result.Severity)
}

func TestTransformWithRiskDisabledKeepsGrypeSeverity(t *testing.T) {
	config := etc.RiskConfig{Risk: etc.RiskConfigData{Enabled: false, Mode: "policy"}}
	tr := NewTransformer(&SystemClock{}, config, policyThresholds, nil)
	report := grype.Report{Matches: []grype.Match{{
		Vulnerability: grype.Vulnerability{ID: "CVE-2023-45288", Severity: "High", Description: "HTTP/2 flood"},
		Artifact:      grype.Artifact{Name: "stdlib", Version: "go1.21.0"},
	}}}

	result := tr.Transform("application/vnd.security.vulnerability.report", testRequest, report)

	require.Len(t, result.Vulnerabilities, 1)
	assert.Equal(t, harbor.SevHigh, result.Vulnerabilities[0].Severity)
	assert.Equal(t, "HTTP/2 flood", result.Vulnerabilities[0].Description)
}

// A finding without a description in the DB shows only the explanation.
func TestTransformPolicyModeWithoutDescription(t *testing.T) {
	report := grype.Report{Matches: []grype.Match{{
		Vulnerability: grype.Vulnerability{ID: "CVE-2099-0101"},
		Artifact:      grype.Artifact{Name: "pkg", Version: "1.0"},
	}}}
	result := policyTransformer(nil).Transform("application/vnd.security.vulnerability.report", testRequest, report)
	require.Len(t, result.Vulnerabilities, 1)
	assert.Equal(t, "Unknown: EPSS нет, критичность grype неизвестна; эксплойтов не найдено; в KEV нет.", result.Vulnerabilities[0].Description)
}

// An Exploit-DB link that the vulnerability already lists is not added twice.
func TestTransformPolicyModeDoesNotDuplicateLinks(t *testing.T) {
	report := grype.Report{Matches: []grype.Match{{
		Vulnerability: grype.Vulnerability{ID: "CVE-2099-0200", Severity: "High", Risk: 40,
			EPSS: []grype.EPSS{{CVE: "CVE-2099-0200", Score: 0.5}},
			URLs: []string{"https://www.exploit-db.com/exploits/1"}},
		Artifact: grype.Artifact{Name: "pkg", Version: "1.0"},
	}}}
	result := policyTransformer(fakeExploits{"CVE-2099-0200": {"1", "2"}}).
		Transform("application/vnd.security.vulnerability.report", testRequest, report)
	require.Len(t, result.Vulnerabilities, 1)
	assert.Equal(t, []string{"https://www.exploit-db.com/exploits/1", "https://www.exploit-db.com/exploits/2"}, result.Vulnerabilities[0].Links)
}
