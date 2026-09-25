package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/grype"
)

type fakeExploits map[string][]string

func (f fakeExploits) Lookup(cve string) []string { return f[cve] }

func TestCVEIDsCollectsEveryCVEOnce(t *testing.T) {
	m := grype.Match{
		Vulnerability: grype.Vulnerability{
			ID:             "ELSA-2099-0001",
			EPSS:           []grype.EPSS{{CVE: "CVE-2099-0002"}, {CVE: "CVE-2099-0001"}},
			KnownExploited: []grype.KnownExploited{{CVE: "CVE-2099-0003"}},
			CWEs:           []grype.CWE{{CVE: "cve-2099-0001", CWE: "CWE-787"}},
		},
		RelatedVulnerabilities: []grype.RelatedVulnerability{{ID: "CVE-2099-0001"}, {ID: "GHSA-xxxx-yyyy-zzzz"}},
	}
	assert.Equal(t, []string{"CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003"}, cveIDs(m))
}

func TestExploitIDsAcrossCVEsAreSortedAndUnique(t *testing.T) {
	lookup := fakeExploits{"CVE-2021-44228": {"50592", "50590"}, "CVE-2021-45046": {"50592", "51183"}}
	assert.Equal(t, []string{"50590", "50592", "51183"}, exploitIDs([]string{"CVE-2021-44228", "CVE-2021-45046"}, lookup))
}

func TestFirstPoCFindsExploitLinksOnly(t *testing.T) {
	m := grype.Match{
		Vulnerability: grype.Vulnerability{URLs: []string{
			"https://github.com/advisories/GHSA-v98v-ff95-f3cp",
			"https://github.com/n8n-io/n8n/security/advisories/GHSA-v98v-ff95-f3cp",
		}},
		RelatedVulnerabilities: []grype.RelatedVulnerability{{URLs: []string{
			"https://nvd.nist.gov/vuln/detail/CVE-2025-15467",
			"https://github.com/guiimoraes/CVE-2025-15467",
		}}},
	}
	assert.Equal(t, "https://github.com/guiimoraes/CVE-2025-15467", firstPoC(m))

	commit := grype.Match{Vulnerability: grype.Vulnerability{URLs: []string{"https://github.com/torvalds/linux/commit/abc"}}}
	assert.Equal(t, "", firstPoC(commit))

	edb := grype.Match{Vulnerability: grype.Vulnerability{URLs: []string{"https://www.exploit-db.com/exploits/52134"}}}
	assert.Equal(t, "https://www.exploit-db.com/exploits/52134", firstPoC(edb))
}

func TestNetworkReachable(t *testing.T) {
	withVectors := func(vectors ...string) grype.Match {
		var c []grype.Cvss
		for _, v := range vectors {
			c = append(c, grype.Cvss{Vector: v})
		}
		return grype.Match{Vulnerability: grype.Vulnerability{Cvss: c}}
	}
	assert.True(t, networkReachable(withVectors("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")))
	assert.True(t, networkReachable(withVectors("AV:N/AC:L/Au:N/C:P/I:P/A:P")), "CVSS v2")
	assert.False(t, networkReachable(withVectors("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")))
	assert.False(t, networkReachable(withVectors("CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/MAV:N")),
		"environmental MAV:N is not the base vector")

	related := grype.Match{RelatedVulnerabilities: []grype.RelatedVulnerability{{
		Cvss: []grype.Cvss{{Vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
	}}}
	assert.True(t, networkReachable(related), "vectors of related CVEs count")
}

func TestMalware(t *testing.T) {
	github := facts{vuln: grype.Vulnerability{Description: "Malware in monorepo-symlink-test"}}
	ok, source := github.malware()
	assert.True(t, ok)
	assert.Equal(t, "github", source)

	xz := facts{vuln: grype.Vulnerability{CWEs: []grype.CWE{{CVE: "CVE-2024-3094", CWE: "CWE-506"}}}}
	ok, source = xz.malware()
	assert.True(t, ok)
	assert.Equal(t, "cwe", source)

	injection := facts{vuln: grype.Vulnerability{Description: "This issue may allow an attacker to inject malicious code into the command"}}
	ok, _ = injection.malware()
	assert.False(t, ok, "wording about malicious input is not malware")
}
