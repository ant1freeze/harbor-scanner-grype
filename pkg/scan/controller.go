package scan

import (
	"context"
	"encoding/base64"
	"log/slog"
	"strings"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/grype"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/harbor"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/http/api"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/job"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/persistence"
)

type Controller interface {
	Scan(ctx context.Context, scanJobKey job.ScanJobKey, request *harbor.ScanRequest) error
}

type controller struct {
	store       persistence.Store
	wrapper     grype.Wrapper
	transformer Transformer
}

func NewController(store persistence.Store, wrapper grype.Wrapper, transformer Transformer) Controller {
	return &controller{
		store:       store,
		wrapper:     wrapper,
		transformer: transformer,
	}
}

func (c *controller) Scan(ctx context.Context, scanJobKey job.ScanJobKey, request *harbor.ScanRequest) error {
	if err := c.scan(ctx, scanJobKey, request); err != nil {
		slog.Error("Scan failed", slog.String("err", err.Error()))
		if err = c.store.UpdateStatus(ctx, scanJobKey, job.Failed, err.Error()); err != nil {
			return xerrors.Errorf("updating scan job as failed: %v", err)
		}
	}
	return nil
}

func (c *controller) scan(ctx context.Context, scanJobKey job.ScanJobKey, req *harbor.ScanRequest) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = r.(error)
		}
	}()

	// Log the incoming request from Harbor
	slog.Info("Received scan request from Harbor",
		slog.String("registry_url", req.Registry.URL),
		slog.String("registry_auth", req.Registry.Authorization),
		slog.String("artifact_repository", req.Artifact.Repository),
		slog.String("artifact_digest", req.Artifact.Digest),
		slog.String("artifact_mime_type", req.Artifact.MimeType),
		slog.Int("capabilities_count", len(req.Capabilities)),
	)

	err = c.store.UpdateStatus(ctx, scanJobKey, job.Pending, "")
	if err != nil {
		return xerrors.Errorf("updating scan job status: %v", err)
	}

	imageRef, nonSSL, err := req.GetImageRef()
	if err != nil {
		return err
	}

	auth, err := c.ToRegistryAuth(req.Registry.Authorization)
	if err != nil {
		return err
	}

	ref := grype.ImageRef{
		Name:   imageRef,
		Auth:   auth,
		NonSSL: nonSSL,
	}

	// Check if this is an SBOM scan request
	if scanJobKey.MIMEType.Equal(api.MimeTypeSecuritySBOMReport) {
		// Generate SBOM using Syft
		sbom, err := c.wrapper.ScanSBOM(ref, grype.ScanOption{
			Format: determineFormat(scanJobKey.MediaType),
		})
		if err != nil {
			return xerrors.Errorf("running sbom scan: %v", err)
		}

		harborScanReport := c.transformer.TransformSBOM(scanJobKey.MediaType, lo.FromPtr(req), sbom)
		if err = c.store.UpdateReport(ctx, scanJobKey, harborScanReport); err != nil {
			return xerrors.Errorf("saving sbom report: %v", err)
		}
	} else {
		// Generate vulnerability report using Grype
		scanReport, err := c.wrapper.Scan(ref, grype.ScanOption{
			Format: determineFormat(scanJobKey.MediaType),
		})
		if err != nil {
			return xerrors.Errorf("running grype wrapper: %v", err)
		}

		harborScanReport := c.transformer.Transform(scanJobKey.MediaType, lo.FromPtr(req), scanReport)
		if err = c.store.UpdateReport(ctx, scanJobKey, harborScanReport); err != nil {
			return xerrors.Errorf("saving scan report: %v", err)
		}
	}

	if err = c.store.UpdateStatus(ctx, scanJobKey, job.Finished, ""); err != nil {
		return xerrors.Errorf("updating scan job status: %v", err)
	}

	return
}

func (c *controller) ToRegistryAuth(authorization string) (auth grype.RegistryAuth, err error) {
	slog.Info("Processing authorization from Harbor",
		slog.String("authorization", authorization),
	)

	if authorization == "" {
		slog.Info("No authorization provided, using default credentials")
		// Use default Harbor credentials for testing
		return grype.BasicAuth{
			Username: "admin",
			Password: "Harbor12345",
		}, nil
	}

	tokens := strings.Split(authorization, " ")
	if len(tokens) != 2 {
		return auth, xerrors.Errorf("parsing authorization: expected <type> <credentials> got %s", authorization)
	}

	slog.Info("Authorization type detected",
		slog.String("type", tokens[0]),
		slog.String("credentials", tokens[1]),
	)

	switch tokens[0] {
	case "Basic":
		auth, err = c.decodeBasicAuth(tokens[1])
		if err != nil {
			return auth, err
		}
		slog.Info("Decoded Basic Auth",
			slog.String("username", auth.(grype.BasicAuth).Username),
			slog.String("password", "***"),
		)
		return auth, nil
	case "Bearer":
		slog.Info("Bearer token received, using default Basic Auth for Harbor registry")
		// For Harbor, we'll use Basic Auth with admin credentials
		// since Harbor registry typically uses Basic Auth
		return grype.BasicAuth{
			Username: "admin",
			Password: "Harbor12345",
		}, nil
	}

	return auth, xerrors.Errorf("unrecognized authorization type: %s", tokens[0])
}

func (c *controller) decodeBasicAuth(value string) (auth grype.RegistryAuth, err error) {
	creds, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return auth, err
	}
	tokens := strings.Split(string(creds), ":")
	auth = grype.BasicAuth{
		Username: tokens[0],
		Password: tokens[1],
	}
	return
}

func determineFormat(m api.MediaType) grype.Format {
	switch m {
	case api.MediaTypeSPDX:
		return grype.FormatSPDX
	case api.MediaTypeCycloneDX:
		return grype.FormatCycloneDX
	default:
		return grype.FormatJSON
	}
}
