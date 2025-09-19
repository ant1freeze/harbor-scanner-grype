package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type MIMEType string

const (
	MimeTypeScanResponse                MIMEType = "application/vnd.scanner.adapter.scan.response+json; version=1.0"
	MimeTypeSecurityVulnerabilityReport MIMEType = "application/vnd.security.vulnerability.report; version=1.1"
	MimeTypeSecuritySBOMReport          MIMEType = "application/vnd.security.sbom.report+json; version=1.0"
	MimeTypeMetadata                    MIMEType = "application/vnd.scanner.adapter.metadata+json; version=1.0"
	MimeTypeOCIImageManifest            MIMEType = "application/vnd.oci.image.manifest.v1+json"
	MimeTypeDockerImageManifestV2       MIMEType = "application/vnd.docker.distribution.manifest.v2+json"
)

type MediaType string

const (
	MediaTypeSPDX      MediaType = "application/spdx+json"
	MediaTypeCycloneDX MediaType = "application/vnd.cyclonedx+json"
)

func (m MIMEType) String() string {
	return string(m)
}

func (m MIMEType) Equal(other MIMEType) bool {
	return strings.EqualFold(string(m), string(other))
}

func (m *MIMEType) Parse(accept string) error {
	accept = strings.TrimSpace(accept)
	if accept == "" {
		*m = MimeTypeSecurityVulnerabilityReport
		return nil
	}

	// Parse Accept header and find the best match
	parts := strings.Split(accept, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "application/vnd.security.vulnerability.report") {
			*m = MimeTypeSecurityVulnerabilityReport
			return nil
		}
		if strings.Contains(part, "application/vnd.security.sbom.report") {
			*m = MimeTypeSecuritySBOMReport
			return nil
		}
	}

	return fmt.Errorf("unsupported media type: %s", accept)
}

const (
	HeaderAccept      = "Accept"
	HeaderContentType = "Content-Type"
)

type Error struct {
	HTTPCode int    `json:"-"`
	Message  string `json:"message"`
}

func (e Error) Error() string {
	return e.Message
}

type BaseHandler struct{}

func (h *BaseHandler) WriteJSON(w http.ResponseWriter, v interface{}, contentType MIMEType, statusCode int) {
	w.Header().Set(HeaderContentType, contentType.String())
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *BaseHandler) WriteJSONError(w http.ResponseWriter, err Error) {
	w.Header().Set(HeaderContentType, "application/json")
	w.WriteHeader(err.HTTPCode)

	response := map[string]interface{}{
		"error": map[string]string{
			"message": err.Message,
		},
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
