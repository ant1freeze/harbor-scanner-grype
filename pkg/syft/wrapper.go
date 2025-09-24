package syft

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/ext"
)

type Format string

const (
	syftCmd = "syft"

	FormatSPDX      Format = "spdx-json"
	FormatCycloneDX Format = "cyclonedx-json"
)

type ImageRef struct {
	Name   string
	Auth   RegistryAuth
	NonSSL bool
}

type ScanOption struct {
	Format Format
}

// RegistryAuth wraps registry credentials.
type RegistryAuth interface {
}

type NoAuth struct {
}

type BasicAuth struct {
	Username string
	Password string
}

type BearerAuth struct {
	Token string
}

type Wrapper interface {
	Scan(imageRef ImageRef, opt ScanOption) (any, error)
}

type wrapper struct {
	config     etc.Grype
	ambassador ext.Ambassador
}

func NewWrapper(config etc.Grype, ambassador ext.Ambassador) Wrapper {
	return &wrapper{
		config:     config,
		ambassador: ambassador,
	}
}

func (w *wrapper) Scan(imageRef ImageRef, opt ScanOption) (any, error) {
	logger := slog.With(slog.String("image_ref", imageRef.Name))
	logger.Debug("Started SBOM scanning with Syft")

	// Try to pull image using Docker first if it's a registry image
	if strings.HasPrefix(imageRef.Name, "registry:") {
		if err := w.pullImageWithDocker(imageRef); err != nil {
			logger.Warn("Failed to pull image with Docker, trying direct Syft scan", slog.String("err", err.Error()))
		} else {
			logger.Debug("Successfully pulled image with Docker")
		}
	}

	cmd, err := w.prepareScanCmd(imageRef, opt)
	if err != nil {
		return nil, xerrors.Errorf("preparing scan command: %w", err)
	}

	// Set up registry authentication via environment variables
	if imageRef.Auth != nil {
		registryURL := w.extractRegistryURL(imageRef.Name)
		if registryURL != "" {
			// Set HTTP registry settings
			cmd.Env = append(cmd.Env, "SYFT_REGISTRY_INSECURE_USE_HTTP=true")
			cmd.Env = append(cmd.Env, "SYFT_REGISTRY_INSECURE_SKIP_TLS_VERIFY=true")

			switch auth := imageRef.Auth.(type) {
			case BasicAuth:
				// Set up basic auth via environment variables
				cmd.Env = append(cmd.Env, fmt.Sprintf("SYFT_REGISTRY_AUTH_AUTHORITY=%s", registryURL))
				cmd.Env = append(cmd.Env, fmt.Sprintf("SYFT_REGISTRY_AUTH_USERNAME=%s", auth.Username))
				cmd.Env = append(cmd.Env, fmt.Sprintf("SYFT_REGISTRY_AUTH_PASSWORD=%s", auth.Password))
			case BearerAuth:
				// Set up bearer token auth via environment variables
				cmd.Env = append(cmd.Env, fmt.Sprintf("SYFT_REGISTRY_AUTH_AUTHORITY=%s", registryURL))
				cmd.Env = append(cmd.Env, fmt.Sprintf("SYFT_REGISTRY_AUTH_TOKEN=%s", auth.Token))
			}
		}
	}

	logger.Info("Exec command with args", slog.String("path", cmd.Path),
		slog.String("args", strings.Join(cmd.Args, " ")),
		slog.String("env", strings.Join(cmd.Env, " ")))

	// Use CombinedOutput to get both stdout and stderr
	output, err := cmd.CombinedOutput()
	exitCode := cmd.ProcessState.ExitCode()

	if err != nil && exitCode != 0 {
		logger.Error("Running syft failed",
			slog.String("exit_code", fmt.Sprintf("%d", exitCode)),
			slog.String("output", string(output)),
		)
		return nil, fmt.Errorf("running syft: %v: %v", err, string(output))
	}

	logger.Info("Running syft finished",
		slog.String("exit_code", fmt.Sprintf("%d", cmd.ProcessState.ExitCode())),
		slog.String("output", string(output)),
	)

	// Parse SBOM from output
	var sbom any
	if err := json.Unmarshal(output, &sbom); err != nil {
		return nil, xerrors.Errorf("sbom json decode error: %w", err)
	}

	return sbom, nil
}

func (w *wrapper) extractImageName(fullImageRef string) string {
	// Extract image name from full registry URL
	// Example: registry-1.docker.io:443/library/alpine@sha256:... -> alpine:latest

	// Remove registry prefix
	if strings.Contains(fullImageRef, "/") {
		parts := strings.Split(fullImageRef, "/")
		if len(parts) >= 2 {
			imagePath := parts[len(parts)-1]
			// Remove @sha256:... part
			if strings.Contains(imagePath, "@") {
				imagePath = strings.Split(imagePath, "@")[0]
			}
			// Add :latest if no tag specified
			if !strings.Contains(imagePath, ":") {
				imagePath += ":latest"
			}
			return imagePath
		}
	}

	// Fallback to original name
	return fullImageRef
}

func (w *wrapper) extractRegistryURL(fullImageRef string) string {
	// Extract registry URL from full image reference
	// Example: registry-1.docker.io:443/library/alpine@sha256:... -> registry-1.docker.io:443

	if strings.Contains(fullImageRef, "/") {
		parts := strings.Split(fullImageRef, "/")
		if len(parts) >= 2 {
			return parts[0]
		}
	}

	return ""
}

func (w *wrapper) pullImageWithDocker(imageRef ImageRef) error {
	// Extract image name from registry URL
	imageName := w.extractImageName(imageRef.Name)

	// Try to pull image using Docker
	cmd := exec.Command("docker", "pull", imageName)

	// Set up authentication if available
	if imageRef.Auth != nil {
		switch auth := imageRef.Auth.(type) {
		case BasicAuth:
			cmd.Env = append(cmd.Env, fmt.Sprintf("DOCKER_USERNAME=%s", auth.Username))
			cmd.Env = append(cmd.Env, fmt.Sprintf("DOCKER_PASSWORD=%s", auth.Password))
		case BearerAuth:
			cmd.Env = append(cmd.Env, fmt.Sprintf("DOCKER_TOKEN=%s", auth.Token))
		}
	}

	// Run docker pull command
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker pull failed: %v: %s", err, string(output))
	}

	return nil
}

func (w *wrapper) prepareScanCmd(imageRef ImageRef, opt ScanOption) (*exec.Cmd, error) {
	// Use the full image reference for Syft
	args := []string{
		imageRef.Name,
		"--output", string(opt.Format),
	}

	name, err := w.ambassador.LookPath(syftCmd)
	if err != nil {
		return nil, err
	}

	cmd := exec.Command(name, args...)
	cmd.Env = w.ambassador.Environ()

	switch a := imageRef.Auth.(type) {
	case NoAuth:
	case BasicAuth:
		cmd.Env = append(cmd.Env,
			fmt.Sprintf("SYFT_REGISTRY_USERNAME=%s", a.Username),
			fmt.Sprintf("SYFT_REGISTRY_PASSWORD=%s", a.Password))
	case BearerAuth:
		cmd.Env = append(cmd.Env,
			fmt.Sprintf("SYFT_REGISTRY_TOKEN=%s", a.Token))
	default:
		return nil, fmt.Errorf("invalid auth type %T", a)
	}

	return cmd, nil
}
