package scan

import (
	"time"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/grype"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/harbor"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/http/api"
)

type Transformer interface {
	Transform(mediaType api.MediaType, request harbor.ScanRequest, report grype.Report) *harbor.ScanReport
}

type transformer struct {
	clock Clock
}

func NewTransformer(clock Clock) Transformer {
	return &transformer{
		clock: clock,
	}
}

type Clock interface {
	Now() time.Time
}

type SystemClock struct{}

func (c *SystemClock) Now() time.Time {
	return time.Now()
}

func (t *transformer) Transform(mediaType api.MediaType, request harbor.ScanRequest, report grype.Report) *harbor.ScanReport {
	scanReport := &harbor.ScanReport{
		GeneratedAt: t.clock.Now(),
		Artifact:    request.Artifact,
		Scanner:     harbor.GetScannerMetadata(),
	}

	if mediaType == api.MediaTypeSPDX || mediaType == api.MediaTypeCycloneDX {
		scanReport.MediaType = mediaType
		scanReport.SBOM = report.SBOM
		return scanReport
	}

	// Transform vulnerabilities
	var vulnerabilities []harbor.VulnerabilityItem
	var maxSeverity harbor.Severity

	for _, vuln := range report.Vulnerabilities {
		vulnerability := harbor.VulnerabilityItem{
			ID:          vuln.ID,
			Description: vuln.Description,
			Links:       vuln.URLs,
		}

		// Map severity
		severity := mapGrypeSeverityToHarbor(vuln.Severity)
		vulnerability.Severity = severity

		// Track max severity
		if severity > maxSeverity {
			maxSeverity = severity
		}

		// Add CVSS information if available
		if len(vuln.Cvss) > 0 {
			cvss := vuln.Cvss[0] // Use first CVSS entry
			vulnerability.PreferredCVSS = &harbor.CVSSDetails{
				VectorV2: cvss.Vector,
				VectorV3: cvss.Vector,
			}
			if cvss.Version == "2.0" {
				score := float32(cvss.Metrics.BaseScore)
				vulnerability.PreferredCVSS.ScoreV2 = &score
			} else if cvss.Version == "3.0" || cvss.Version == "3.1" {
				score := float32(cvss.Metrics.BaseScore)
				vulnerability.PreferredCVSS.ScoreV3 = &score
			}
		}

		vulnerabilities = append(vulnerabilities, vulnerability)
	}

	scanReport.Vulnerabilities = vulnerabilities
	scanReport.Severity = maxSeverity

	return scanReport
}

func mapGrypeSeverityToHarbor(severity string) harbor.Severity {
	switch severity {
	case "Critical":
		return harbor.SevCritical
	case "High":
		return harbor.SevHigh
	case "Medium":
		return harbor.SevMedium
	case "Low":
		return harbor.SevLow
	default:
		return harbor.SevUnknown
	}
}
