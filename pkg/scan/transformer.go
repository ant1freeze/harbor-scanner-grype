package scan

import (
	"fmt"
	"time"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/grype"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/harbor"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/http/api"
)

type Transformer interface {
	Transform(mediaType api.MediaType, request harbor.ScanRequest, report grype.Report) *harbor.ScanReport
	TransformSBOM(mediaType api.MediaType, request harbor.ScanRequest, sbom any) *harbor.ScanReport
}

type transformer struct {
	clock  Clock
	config etc.RiskConfig
}

func NewTransformer(clock Clock, config etc.RiskConfig) Transformer {
	return &transformer{
		clock:  clock,
		config: config,
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
	// Debug: Print configuration
	// Risk calculation configuration loaded

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
		// Find corresponding match for this vulnerability to get package info
		var match *grype.Match
		for _, m := range report.Matches {
			if m.Vulnerability.ID == vuln.ID {
				match = &m
				break
			}
		}

		// Calculate severity based on configuration
		var severity harbor.Severity
		var riskInfo string
		if t.config.Risk.Enabled {
			severity, riskInfo = t.calculateSeverityWithInfo(vuln)
		} else {
			severity = mapGrypeSeverityToHarbor(vuln.Severity)
			riskInfo = ""
		}

		// Create description with risk calculation info
		description := vuln.Description
		if riskInfo != "" {
			description = vuln.Description + riskInfo
		}

		vulnerability := harbor.VulnerabilityItem{
			ID:          vuln.ID,
			Description: description,
			Links:       vuln.URLs,
			Severity:    severity,
		}

		// Fill package information if match is found
		if match != nil {
			vulnerability.Pkg = match.Artifact.Name
			vulnerability.Version = match.Artifact.Version

			// Set fix version from vulnerability fix information
			if len(vuln.Fix.Versions) > 0 {
				vulnerability.FixVersion = vuln.Fix.Versions[0]
			}
		}

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

// calculateSeverity calculates severity based on configured mode
func (t *transformer) calculateSeverity(vuln grype.Vulnerability) harbor.Severity {
	switch t.config.Risk.Mode {
	case "formula":
		return t.calculateRiskBasedSeverity(vuln)
	case "cvss":
		return t.calculateCVSSBasedSeverity(vuln)
	default:
		// Fallback to original Grype severity
		return mapGrypeSeverityToHarbor(vuln.Severity)
	}
}

// calculateSeverityWithInfo calculates severity and returns risk calculation info
func (t *transformer) calculateSeverityWithInfo(vuln grype.Vulnerability) (harbor.Severity, string) {
	switch t.config.Risk.Mode {
	case "formula":
		return t.calculateRiskBasedSeverityWithInfo(vuln)
	case "cvss":
		return t.calculateCVSSBasedSeverityWithInfo(vuln)
	default:
		// Fallback to original Grype severity
		return mapGrypeSeverityToHarbor(vuln.Severity), ""
	}
}

// calculateRiskBasedSeverity calculates severity based on Risk = EPSS * (CVSS/10)
func (t *transformer) calculateRiskBasedSeverity(vuln grype.Vulnerability) harbor.Severity {
	severity, _ := t.calculateRiskBasedSeverityWithInfo(vuln)
	return severity
}

// calculateRiskBasedSeverityWithInfo calculates severity and returns risk calculation info
func (t *transformer) calculateRiskBasedSeverityWithInfo(vuln grype.Vulnerability) (harbor.Severity, string) {
	// Get EPSS score
	epssScore := t.getEPSSScore(vuln)

	// Get CVSS score
	cvssScore := t.getCVSSScore(vuln)

	// Calculate risk: Risk = EPSS * (CVSS/10)
	// EPSS is in decimal format (0.006460 = 0.646%), so we multiply by 100 to get percentage
	riskPercentage := epssScore * 100 * (cvssScore / 10.0)

	// Determine severity based on thresholds
	severity := t.mapRiskToSeverity(riskPercentage)

	// Create risk calculation info
	riskInfo := fmt.Sprintf(" [RISK: %.3f%%] EPSS: %.6f%% × CVSS: %.1f ÷ 10 = %.3f%% → %s",
		riskPercentage, epssScore*100, cvssScore, riskPercentage, severity.String())

	return severity, riskInfo
}

// calculateCVSSBasedSeverity calculates severity based on CVSS score only
func (t *transformer) calculateCVSSBasedSeverity(vuln grype.Vulnerability) harbor.Severity {
	severity, _ := t.calculateCVSSBasedSeverityWithInfo(vuln)
	return severity
}

// calculateCVSSBasedSeverityWithInfo calculates severity based on CVSS score and returns calculation info
func (t *transformer) calculateCVSSBasedSeverityWithInfo(vuln grype.Vulnerability) (harbor.Severity, string) {
	// Get CVSS score
	cvssScore := t.getCVSSScore(vuln)

	// Map CVSS score to severity based on configured thresholds
	severity := t.mapCVSSToSeverity(cvssScore)

	// Create CVSS calculation info
	riskInfo := fmt.Sprintf(" [CVSS: %.1f] Direct CVSS scoring → %s",
		cvssScore, severity.String())

	return severity, riskInfo
}

// getEPSSScore extracts EPSS score from vulnerability
func (t *transformer) getEPSSScore(vuln grype.Vulnerability) float64 {
	// Try to get EPSS from main vulnerability first
	if len(vuln.EPSS) > 0 && vuln.EPSS[0].Score > 0 {
		return vuln.EPSS[0].Score
	}

	// Try to get EPSS from related vulnerabilities
	for _, related := range vuln.RelatedVulnerabilities {
		if len(related.EPSS) > 0 && related.EPSS[0].Score > 0 {
			return related.EPSS[0].Score
		}
	}

	// Return default EPSS if not available
	return t.config.Risk.Defaults.EPSS
}

// getCVSSScore extracts CVSS score from vulnerability
func (t *transformer) getCVSSScore(vuln grype.Vulnerability) float64 {
	// Try to get CVSS v3 score first, then v2 from main vulnerability
	for _, cvss := range vuln.Cvss {
		if cvss.Version == "3.0" || cvss.Version == "3.1" {
			return cvss.Metrics.BaseScore
		}
	}

	// Fallback to CVSS v2 from main vulnerability
	for _, cvss := range vuln.Cvss {
		if cvss.Version == "2.0" {
			return cvss.Metrics.BaseScore
		}
	}

	// Try to get CVSS from related vulnerabilities
	for _, related := range vuln.RelatedVulnerabilities {
		// Try CVSS v3 first
		for _, cvss := range related.Cvss {
			if cvss.Version == "3.0" || cvss.Version == "3.1" {
				return cvss.Metrics.BaseScore
			}
		}
		// Fallback to CVSS v2
		for _, cvss := range related.Cvss {
			if cvss.Version == "2.0" {
				return cvss.Metrics.BaseScore
			}
		}
	}

	// Return default CVSS if not available
	return t.config.Risk.Defaults.CVSS
}

// mapRiskToSeverity maps risk percentage to Harbor severity
func (t *transformer) mapRiskToSeverity(riskPercentage float64) harbor.Severity {
	if riskPercentage >= t.config.Risk.Thresholds.Critical {
		return harbor.SevCritical
	} else if riskPercentage >= t.config.Risk.Thresholds.High {
		return harbor.SevHigh
	} else if riskPercentage >= t.config.Risk.Thresholds.Medium {
		return harbor.SevMedium
	} else if riskPercentage >= t.config.Risk.Thresholds.Low {
		return harbor.SevLow
	}
	return harbor.SevUnknown
}

// mapCVSSToSeverity maps CVSS score to Harbor severity
func (t *transformer) mapCVSSToSeverity(cvssScore float64) harbor.Severity {
	if cvssScore >= t.config.Risk.CVSSThresholds.Critical {
		return harbor.SevCritical
	} else if cvssScore >= t.config.Risk.CVSSThresholds.High {
		return harbor.SevHigh
	} else if cvssScore >= t.config.Risk.CVSSThresholds.Medium {
		return harbor.SevMedium
	} else if cvssScore >= t.config.Risk.CVSSThresholds.Low {
		return harbor.SevLow
	}
	return harbor.SevUnknown
}

func (t *transformer) TransformSBOM(mediaType api.MediaType, request harbor.ScanRequest, sbom any) *harbor.ScanReport {
	return &harbor.ScanReport{
		GeneratedAt: t.clock.Now(),
		Artifact:    request.Artifact,
		Scanner:     harbor.GetScannerMetadata(),
		MediaType:   mediaType,
		SBOM:        sbom,
	}
}
