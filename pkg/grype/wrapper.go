package grype

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/ext"
)

type Format string

const (
	grypeCmd = "grype"

	FormatJSON      Format = "json"
	FormatSPDX      Format = "spdx-json"
	FormatCycloneDX Format = "cyclonedx"
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
	Scan(imageRef ImageRef, opt ScanOption) (Report, error)
	ScanSBOM(imageRef ImageRef, opt ScanOption) (any, error)
	GetVersion() (VersionInfo, error)
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

func (w *wrapper) Scan(imageRef ImageRef, opt ScanOption) (Report, error) {
	logger := slog.With(slog.String("image_ref", imageRef.Name))
	logger.Debug("Started scanning")

	// Try to pull image using Docker first if it's a registry image
	if strings.HasPrefix(imageRef.Name, "registry:") {
		if err := w.pullImageWithDocker(imageRef); err != nil {
			logger.Warn("Failed to pull image with Docker, trying direct Grype scan", slog.String("err", err.Error()))
		} else {
			logger.Debug("Successfully pulled image with Docker")
		}
	}

	reportFile, err := w.ambassador.TempFile(w.config.ReportsDir, "scan_report_*.json")
	if err != nil {
		return Report{}, xerrors.Errorf("creating scan report tmp file: %w", err)
	}
	logger.Debug("Saving scan report to tmp file", slog.String("path", reportFile.Name()))
	defer func() {
		if err = reportFile.Close(); err != nil {
			logger.Warn("Error while closing scan report tmp file", slog.String("err", err.Error()))
		}
		logger.Debug("Removing scan report tmp file", slog.String("path", reportFile.Name()))
		if err = os.Remove(reportFile.Name()); err != nil {
			logger.Warn("Error while removing scan report tmp file", slog.String("err", err.Error()))
		}
	}()

	cmd, err := w.prepareScanCmd(imageRef, reportFile.Name(), opt)
	if err != nil {
		return Report{}, xerrors.Errorf("preparing scan command: %w", err)
	}

	// Set up registry authentication via environment variables
	if imageRef.Auth != nil {
		registryURL := w.extractRegistryURL(imageRef.Name)
		if registryURL != "" {
			// Set HTTP registry settings
			cmd.Env = append(cmd.Env, "GRYPE_REGISTRY_INSECURE_USE_HTTP=true")
			cmd.Env = append(cmd.Env, "GRYPE_REGISTRY_INSECURE_SKIP_TLS_VERIFY=true")

			switch auth := imageRef.Auth.(type) {
			case BasicAuth:
				// Set up basic auth via environment variables
				cmd.Env = append(cmd.Env, fmt.Sprintf("GRYPE_REGISTRY_AUTH_AUTHORITY=%s", registryURL))
				cmd.Env = append(cmd.Env, fmt.Sprintf("GRYPE_REGISTRY_AUTH_USERNAME=%s", auth.Username))
				cmd.Env = append(cmd.Env, fmt.Sprintf("GRYPE_REGISTRY_AUTH_PASSWORD=%s", auth.Password))
			case BearerAuth:
				// Set up bearer token auth via environment variables
				cmd.Env = append(cmd.Env, fmt.Sprintf("GRYPE_REGISTRY_AUTH_AUTHORITY=%s", registryURL))
				cmd.Env = append(cmd.Env, fmt.Sprintf("GRYPE_REGISTRY_AUTH_TOKEN=%s", auth.Token))
			}
		}
	}

	logger.Info("Exec command with args", slog.String("path", cmd.Path),
		slog.String("args", strings.Join(cmd.Args, " ")),
		slog.String("env", strings.Join(cmd.Env, " ")))

	// Use CombinedOutput to get both stdout and stderr
	output, err := cmd.CombinedOutput()
	exitCode := cmd.ProcessState.ExitCode()

	// Grype may return exit code 1 or 2 when vulnerabilities are found, but this is not an error
	// We should only treat it as an error if there's no output or if exit code is > 2
	if err != nil && (exitCode > 2 || len(output) == 0) {
		logger.Error("Running grype failed",
			slog.String("exit_code", fmt.Sprintf("%d", exitCode)),
			slog.String("output", string(output)),
		)
		return Report{}, fmt.Errorf("running grype: %v: %v", err, string(output))
	}

	logger.Info("Running grype finished",
		slog.String("exit_code", fmt.Sprintf("%d", cmd.ProcessState.ExitCode())),
		slog.String("output", string(output)),
	)

	// Clean the output by removing any trailing error messages that might break JSON parsing
	cleanOutput := w.cleanGrypeOutput(output)

	// Parse from output instead of file since our mock returns JSON to stdout
	return w.parseReportFromStdout(opt.Format, cleanOutput)
}

func (w *wrapper) cleanGrypeOutput(output []byte) []byte {
	// Convert to string and find the last complete JSON object
	outputStr := string(output)

	// Find the last occurrence of '}' which should be the end of the JSON
	lastBrace := strings.LastIndex(outputStr, "}")
	if lastBrace == -1 {
		return output
	}

	// Find the first occurrence of '{' to get the start of the JSON
	firstBrace := strings.Index(outputStr, "{")
	if firstBrace == -1 {
		return output
	}

	// Extract the JSON part (from first '{' to last '}')
	jsonPart := outputStr[firstBrace : lastBrace+1]

	return []byte(jsonPart)
}

func (w *wrapper) parseReport(format Format, reportFile io.Reader) (Report, error) {
	switch format {
	case FormatJSON:
		return w.parseJSONReport(reportFile)
	case FormatSPDX, FormatCycloneDX:
		return w.parseSBOM(reportFile)
	}
	return Report{}, xerrors.Errorf("unsupported format %s", format)
}

func (w *wrapper) parseReportFromStdout(format Format, stdout []byte) (Report, error) {
	switch format {
	case FormatJSON:
		return w.parseJSONReportFromBytes(stdout)
	case FormatSPDX, FormatCycloneDX:
		return w.parseSBOMFromBytes(stdout)
	}
	return Report{}, xerrors.Errorf("unsupported format %s", format)
}

func (w *wrapper) parseJSONReport(reportFile io.Reader) (Report, error) {
	var scanReport ScanReport
	if err := json.NewDecoder(reportFile).Decode(&scanReport); err != nil {
		return Report{}, xerrors.Errorf("report json decode error: %w", err)
	}

	var vulnerabilities []Vulnerability
	for _, match := range scanReport.Matches {
		slog.Debug("Parsing vulnerabilities", slog.String("target", fmt.Sprintf("%v", scanReport.Source.Target)))
		vulnerabilities = append(vulnerabilities, match.Vulnerability)
	}

	return Report{
		Vulnerabilities: vulnerabilities,
		Matches:         scanReport.Matches,
	}, nil
}

func (w *wrapper) parseJSONReportFromBytes(data []byte) (Report, error) {
	var scanReport ScanReport
	if err := json.Unmarshal(data, &scanReport); err != nil {
		return Report{}, xerrors.Errorf("report json decode error: %w", err)
	}

	var vulnerabilities []Vulnerability
	for _, match := range scanReport.Matches {
		slog.Debug("Parsing vulnerabilities", slog.String("target", fmt.Sprintf("%v", scanReport.Source.Target)))
		vulnerabilities = append(vulnerabilities, match.Vulnerability)
	}

	return Report{
		Vulnerabilities: vulnerabilities,
		Matches:         scanReport.Matches,
	}, nil
}

func (w *wrapper) parseSBOM(reportFile io.Reader) (Report, error) {
	var doc any
	if err := json.NewDecoder(reportFile).Decode(&doc); err != nil {
		return Report{}, xerrors.Errorf("sbom json decode error: %w", err)
	}
	return Report{SBOM: doc}, nil
}

func (w *wrapper) parseSBOMFromBytes(data []byte) (Report, error) {
	var doc any
	if err := json.Unmarshal(data, &doc); err != nil {
		return Report{}, xerrors.Errorf("sbom json decode error: %w", err)
	}
	return Report{SBOM: doc}, nil
}

func (w *wrapper) extractImageName(fullImageRef string) string {
	// Extract image name from full registry URL
	// Example: registry-1.docker.io:443/library/alpine@sha256:... -> alpine:latest
	// Example: registry-1.docker.io:443/library/nginx@sha256:... -> nginx:latest

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

func (w *wrapper) prepareScanCmd(imageRef ImageRef, outputFile string, opt ScanOption) (*exec.Cmd, error) {
	// Use the full image reference for Grype
	args := []string{
		imageRef.Name,
		"--output", string(opt.Format),
	}

	if w.config.Severity != "" {
		// --fail-on accepts only one severity level, not a comma-separated list
		// We'll use the first severity level if multiple are provided
		severities := strings.Split(w.config.Severity, ",")
		if len(severities) > 0 && strings.TrimSpace(severities[0]) != "" {
			severity := strings.TrimSpace(severities[0])
			// Map severity levels to valid Grype values
			switch strings.ToLower(severity) {
			case "unknown":
				severity = "negligible"
			case "low":
				severity = "low"
			case "medium":
				severity = "medium"
			case "high":
				severity = "high"
			case "critical":
				severity = "critical"
			default:
				severity = "negligible" // default to lowest severity
			}
			args = append(args, "--fail-on", severity)
		}
	}

	if w.config.IgnoreUnfixed {
		args = append(args, "--ignore-unfixed")
	}

	if w.config.OnlyFixed {
		args = append(args, "--only-fixed")
	}

	if w.config.SkipUpdate {
		args = append(args, "--skip-db-update")
	}

	if w.config.OfflineScan {
		args = append(args, "--offline")
	}

	// Note: Grype doesn't support --insecure flag
	// Registry security settings are handled via environment variables

	if w.config.ConfigFile != "" {
		args = append(args, "--config", w.config.ConfigFile)
	}

	if w.config.FailOnSeverity != "" {
		args = append(args, "--fail-on", w.config.FailOnSeverity)
	}

	if w.config.AddCPEsIfNone {
		args = append(args, "--add-cpes-if-none")
	}

	if w.config.ByCVE {
		args = append(args, "--by-cve")
	}

	if w.config.Platform != "" {
		args = append(args, "--platform", w.config.Platform)
	}

	if w.config.Distro != "" {
		args = append(args, "--distro", w.config.Distro)
	}

	if w.config.ExcludeAddl != "" {
		args = append(args, "--exclude-addl", w.config.ExcludeAddl)
	}

	// Registry authentication is handled in the Scan method via environment variables

	if w.config.DebugMode {
		args = append(args, "--verbose")
	}

	name, err := w.ambassador.LookPath(grypeCmd)
	if err != nil {
		return nil, err
	}

	cmd := exec.Command(name, args...)

	cmd.Env = w.ambassador.Environ()

	switch a := imageRef.Auth.(type) {
	case NoAuth:
	case BasicAuth:
		cmd.Env = append(cmd.Env,
			fmt.Sprintf("GRYPE_REGISTRY_USERNAME=%s", a.Username),
			fmt.Sprintf("GRYPE_REGISTRY_PASSWORD=%s", a.Password))
	case BearerAuth:
		cmd.Env = append(cmd.Env,
			fmt.Sprintf("GRYPE_REGISTRY_TOKEN=%s", a.Token))
	default:
		return nil, fmt.Errorf("invalid auth type %T", a)
	}

	return cmd, nil
}

func (w *wrapper) GetVersion() (VersionInfo, error) {
	cmd, err := w.prepareVersionCmd()
	if err != nil {
		return VersionInfo{}, fmt.Errorf("failed preparing grype version command: %w", err)
	}

	versionOutput, err := w.ambassador.RunCmd(cmd)
	if err != nil {
		return VersionInfo{}, fmt.Errorf("failed running grype version command: %w: %v", err, string(versionOutput))
	}

	var vi VersionInfo
	err = json.Unmarshal(versionOutput, &vi)
	if err != nil {
		return VersionInfo{}, fmt.Errorf("failed parsing grype version output: %w", err)
	}

	return vi, nil
}

func (w *wrapper) prepareVersionCmd() (*exec.Cmd, error) {
	args := []string{
		"version",
		"--output", "json",
	}

	name, err := w.ambassador.LookPath(grypeCmd)
	if err != nil {
		return nil, err
	}

	cmd := exec.Command(name, args...)
	return cmd, nil
}

func (w *wrapper) ScanSBOM(imageRef ImageRef, opt ScanOption) (any, error) {
	logger := slog.With(slog.String("image_ref", imageRef.Name))
	logger.Debug("Started SBOM scanning")

	// Try to pull image using Docker first if it's a registry image
	if strings.HasPrefix(imageRef.Name, "registry:") {
		if err := w.pullImageWithDocker(imageRef); err != nil {
			logger.Warn("Failed to pull image with Docker, trying direct scan", slog.String("err", err.Error()))
		} else {
			logger.Debug("Successfully pulled image with Docker")
		}
	}

	cmd, err := w.prepareSBOMScanCmd(imageRef, opt)
	if err != nil {
		return nil, xerrors.Errorf("preparing SBOM scan command: %w", err)
	}

	// Set up registry authentication via environment variables
	if imageRef.Auth != nil {
		registryURL := w.extractRegistryURL(imageRef.Name)
		if registryURL != "" {
			// Set HTTP registry settings
			cmd.Env = append(cmd.Env, "GRYPE_REGISTRY_INSECURE_USE_HTTP=true")
			cmd.Env = append(cmd.Env, "GRYPE_REGISTRY_INSECURE_SKIP_TLS_VERIFY=true")

			switch auth := imageRef.Auth.(type) {
			case BasicAuth:
				// Set up basic auth via environment variables
				cmd.Env = append(cmd.Env, fmt.Sprintf("GRYPE_REGISTRY_AUTH_AUTHORITY=%s", registryURL))
				cmd.Env = append(cmd.Env, fmt.Sprintf("GRYPE_REGISTRY_AUTH_USERNAME=%s", auth.Username))
				cmd.Env = append(cmd.Env, fmt.Sprintf("GRYPE_REGISTRY_AUTH_PASSWORD=%s", auth.Password))
			case BearerAuth:
				// Set up bearer token auth via environment variables
				cmd.Env = append(cmd.Env, fmt.Sprintf("GRYPE_REGISTRY_AUTH_AUTHORITY=%s", registryURL))
				cmd.Env = append(cmd.Env, fmt.Sprintf("GRYPE_REGISTRY_AUTH_TOKEN=%s", auth.Token))
			}
		}
	}

	logger.Info("Exec SBOM command with args", slog.String("path", cmd.Path),
		slog.String("args", strings.Join(cmd.Args, " ")),
		slog.String("env", strings.Join(cmd.Env, " ")))

	// Use CombinedOutput to get both stdout and stderr
	output, err := cmd.CombinedOutput()
	exitCode := cmd.ProcessState.ExitCode()

	if err != nil && exitCode != 0 {
		logger.Error("Running SBOM scan failed",
			slog.String("exit_code", fmt.Sprintf("%d", exitCode)),
			slog.String("output", string(output)),
		)
		return nil, fmt.Errorf("running SBOM scan: %v: %v", err, string(output))
	}

	logger.Info("Running SBOM scan finished",
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

func (w *wrapper) prepareSBOMScanCmd(imageRef ImageRef, opt ScanOption) (*exec.Cmd, error) {
	// Use Syft for SBOM generation instead of Grype
	args := []string{
		imageRef.Name,
		"--output", string(opt.Format),
	}

	name, err := w.ambassador.LookPath("syft")
	if err != nil {
		return nil, err
	}

	cmd := exec.Command(name, args...)
	cmd.Env = w.ambassador.Environ()

	// Add Syft-specific environment variables for insecure registries
	cmd.Env = append(cmd.Env, "SYFT_REGISTRY_INSECURE_SKIP_TLS_VERIFY=true")
	cmd.Env = append(cmd.Env, "SYFT_REGISTRY_INSECURE_USE_HTTP=true")

	// Set up registry authentication for Syft
	if imageRef.Auth != nil {
		registryURL := w.extractRegistryURL(imageRef.Name)
		if registryURL != "" {
			switch auth := imageRef.Auth.(type) {
			case BasicAuth:
				// Set up basic auth via environment variables for Syft
				cmd.Env = append(cmd.Env, fmt.Sprintf("SYFT_REGISTRY_AUTH_AUTHORITY=%s", registryURL))
				cmd.Env = append(cmd.Env, fmt.Sprintf("SYFT_REGISTRY_AUTH_USERNAME=%s", auth.Username))
				cmd.Env = append(cmd.Env, fmt.Sprintf("SYFT_REGISTRY_AUTH_PASSWORD=%s", auth.Password))
			case BearerAuth:
				// Set up bearer token auth via environment variables for Syft
				cmd.Env = append(cmd.Env, fmt.Sprintf("SYFT_REGISTRY_AUTH_AUTHORITY=%s", registryURL))
				cmd.Env = append(cmd.Env, fmt.Sprintf("SYFT_REGISTRY_AUTH_TOKEN=%s", auth.Token))
			}
		}
	}

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
