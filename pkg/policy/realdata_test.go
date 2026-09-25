package policy

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/grype"
)

func realMatches(t *testing.T) []grype.Match {
	t.Helper()
	files, err := filepath.Glob("testdata/grype-*.json")
	require.NoError(t, err)
	require.NotEmpty(t, files, "run Task 12 of the plan to create the fixtures")
	var all []grype.Match
	for _, file := range files {
		data, err := os.ReadFile(file)
		require.NoError(t, err)
		var doc struct {
			Matches []grype.Match `json:"matches"`
		}
		require.NoError(t, json.Unmarshal(data, &doc), file)
		all = append(all, doc.Matches...)
	}
	return all
}

// The rescaling for advisories reuses grype's formula; on real scans the formula must give
// exactly the risk grype reported.
func TestSeverityFactorAgreesWithGrypeOnRealScans(t *testing.T) {
	checked := 0
	for _, m := range realMatches(t) {
		v := m.Vulnerability
		if len(v.EPSS) == 0 || len(v.KnownExploited) > 0 {
			continue
		}
		want := math.Min(v.EPSS[0].Score*severityFactor(v.Severity, v.Cvss), 1) * 100
		assert.InDelta(t, want, v.Risk, 1e-6, "%s in %s", v.ID, m.Artifact.Name)
		checked++
	}
	assert.Greater(t, checked, 10)
}

// The Amazon Linux 2 advisory lists two CVEs and the first EPSS is not the highest: the policy
// rescales it and never goes below grype's own number.
func TestRescaleHappensOnARealAdvisory(t *testing.T) {
	rescaled := 0
	for _, m := range realMatches(t) {
		est := estimateRisk(m.Vulnerability)
		assert.GreaterOrEqual(t, est.value, est.reported-1e-9, m.Vulnerability.ID)
		if est.rescaled {
			rescaled++
		}
	}
	assert.GreaterOrEqual(t, rescaled, 1)
}

func TestEvaluateExplainsEveryRealFinding(t *testing.T) {
	asOf := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	for _, m := range realMatches(t) {
		res := Evaluate(m, nil, Thresholds{Critical: 70, High: 30, Medium: 10}, asOf)
		assert.True(t, strings.HasPrefix(res.Reason, res.Severity.String()+" на 2026-09-25: "), res.Reason)
		assert.True(t, strings.HasSuffix(res.Reason, "."), res.Reason)
		assert.LessOrEqual(t, utf8.RuneCountInString(res.Reason), 300, res.Reason)
		for _, bad := range []string{"%!", "  ", "..", "\n"} {
			assert.NotContains(t, res.Reason, bad, res.Reason)
		}
	}
}
