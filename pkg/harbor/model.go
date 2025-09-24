package harbor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/http/api"
)

// Severity represents the severity of a image/component in terms of vulnerability.
type Severity int64

// Sevxxx is the list of severity of image after scanning.
const (
	_ Severity = iota
	SevUnknown
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

func (s Severity) String() string {
	return severityToString[s]
}

var severityToString = map[Severity]string{
	SevUnknown:  "Unknown",
	SevLow:      "Low",
	SevMedium:   "Medium",
	SevHigh:     "High",
	SevCritical: "Critical",
}

var stringToSeverity = map[string]Severity{
	"Unknown":  SevUnknown,
	"Low":      SevLow,
	"Medium":   SevMedium,
	"High":     SevHigh,
	"Critical": SevCritical,
}

// MarshalJSON marshals the Severity enum value as a quoted JSON string.
func (s Severity) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString(`"`)
	buffer.WriteString(severityToString[s])
	buffer.WriteString(`"`)
	return buffer.Bytes(), nil
}

// UnmarshalJSON unmarshals quoted JSON string to the Severity enum value.
func (s *Severity) UnmarshalJSON(b []byte) error {
	var value string
	err := json.Unmarshal(b, &value)
	if err != nil {
		return err
	}
	*s = stringToSeverity[value]
	return nil
}

type CapabilityType string

const (
	CapabilityTypeSBOM          CapabilityType = "sbom"
	CapabilityTypeVulnerability CapabilityType = "vulnerability"
)

var SupportedSBOMMediaTypes = []api.MediaType{
	api.MediaTypeSPDX,
	api.MediaTypeCycloneDX,
}

type Registry struct {
	URL           string `json:"url"`
	Authorization string `json:"authorization"`
}

type Artifact struct {
	Repository string `json:"repository"`
	Digest     string `json:"digest"`
	MimeType   string `json:"mime_type,omitempty"`
}

// ScanReportQuery is a struct for the query parameters at "/scan/{scan_request_id}/report".
type ScanReportQuery struct {
	SBOMMediaType api.MediaType `schema:"sbom_media_type"`
}

type ScanRequest struct {
	Registry     Registry     `json:"registry"`
	Artifact     Artifact     `json:"artifact"`
	Capabilities []Capability `json:"enabled_capabilities"`
}

// GetImageRef returns Docker image reference for this ScanRequest.
// Example: core.harbor.domain/scanners/mysql@sha256:3b00a364fb74246ca119d16111eb62f7302b2ff66d51e373c2bb209f8a1f3b9e
func (c ScanRequest) GetImageRef() (imageRef string, nonSSL bool, err error) {
	registryURL, err := url.Parse(c.Registry.URL)
	if err != nil {
		err = fmt.Errorf("parsing registry URL: %w", err)
		return
	}

	port := registryURL.Port()
	if port == "" && registryURL.Scheme == "http" {
		port = "80"
	}
	if port == "" && registryURL.Scheme == "https" {
		port = "443"
	}

	// Use the hostname that Harbor provides in the request
	hostname := registryURL.Hostname()

	fmt.Printf("DEBUG: Original URL: %s, hostname: %s, port: %s\n", c.Registry.URL, hostname, port)

	// Fix hostname to use internal Docker network names
	// Note: For SBOM scanning, we should use the original hostname that Harbor provides
	// because Harbor needs to access the registry using the external address
	if hostname == "localhost" {
		hostname = "nginx"
		port = "8080"
		fmt.Printf("DEBUG: Mapped localhost to nginx:8080\n")
	} else if hostname == "harbor.corp.local" {
		// Keep original hostname for SBOM scanning - Harbor needs external access
		// Harbor is configured to force HTTPS, so use port 443
		port = "443"
		fmt.Printf("DEBUG: Keeping original hostname harbor.corp.local for SBOM scanning, using HTTPS port 443\n")
	}

	// If no port specified, use default ports
	if port == "" && registryURL.Scheme == "http" {
		port = "80"
	}
	if port == "" && registryURL.Scheme == "https" {
		port = "443"
	}

	// Format for Grype registry: hostname:port/repository
	imageRef = fmt.Sprintf("%s:%s/%s@%s", hostname, port, c.Artifact.Repository, c.Artifact.Digest)

	// Set nonSSL flag - use HTTPS for harbor.corp.local, HTTP for others
	if hostname == "harbor.corp.local" {
		nonSSL = false // Use HTTPS for harbor.corp.local
	} else {
		nonSSL = "http" == registryURL.Scheme
	}

	fmt.Printf("DEBUG: Final imageRef: %s\n", imageRef)
	return
}

type ScanResponse struct {
	ID string `json:"id"`
}

type ScanReport struct {
	GeneratedAt time.Time `json:"generated_at"`
	Artifact    Artifact  `json:"artifact"`
	Scanner     Scanner   `json:"scanner"`
	Severity    Severity  `json:"severity,omitempty"`

	// For SBOM
	MediaType api.MediaType `json:"media_type,omitempty"`
	SBOM      any           `json:"sbom,omitempty"`

	// For vulnerabilities
	Vulnerabilities []VulnerabilityItem `json:"vulnerabilities,omitempty"`
}

type Layer struct {
	Digest string `json:"digest,omitempty"`
	DiffID string `json:"diff_id,omitempty"`
}

type CVSSDetails struct {
	ScoreV2  *float32 `json:"score_v2,omitempty"`
	ScoreV3  *float32 `json:"score_v3,omitempty"`
	VectorV2 string   `json:"vector_v2"`
	VectorV3 string   `json:"vector_v3"`
}

// VulnerabilityItem is an item in the vulnerability result returned by vulnerability details API.
type VulnerabilityItem struct {
	ID               string         `json:"id"`
	Pkg              string         `json:"package"`
	Version          string         `json:"version"`
	FixVersion       string         `json:"fix_version,omitempty"`
	Severity         Severity       `json:"severity"`
	Description      string         `json:"description"`
	Links            []string       `json:"links"`
	Layer            *Layer         `json:"layer"` // Not defined by Scanners API
	PreferredCVSS    *CVSSDetails   `json:"preferred_cvss,omitempty"`
	CweIDs           []string       `json:"cwe_ids,omitempty"`
	VendorAttributes map[string]any `json:"vendor_attributes,omitempty"`
}

type ScannerAdapterMetadata struct {
	Scanner      Scanner           `json:"scanner"`
	Capabilities []Capability      `json:"capabilities"`
	Properties   map[string]string `json:"properties"`
}

type Scanner struct {
	Name    string `json:"name"`
	Vendor  string `json:"vendor"`
	Version string `json:"version"`
}

type Capability struct {
	Type              CapabilityType `json:"type"`
	ConsumesMIMETypes []string       `json:"consumes_mime_types"`
	ProducesMIMETypes []api.MIMEType `json:"produces_mime_types"`

	// For /metadata
	AdditionalAttributes *CapabilityAttributes `json:"additional_attributes,omitempty"`

	// For /scan
	Parameters *CapabilityAttributes `json:"parameters,omitempty"`
}

type CapabilityAttributes struct {
	SBOMMediaTypes []api.MediaType `json:"sbom_media_types,omitempty"`
}

func GetScannerMetadata() Scanner {
	version, ok := os.LookupEnv("GRYPE_VERSION")
	if !ok {
		version = "Unknown"
	}
	return Scanner{
		Name:    "Grype",
		Vendor:  "Anchore",
		Version: version,
	}
}
