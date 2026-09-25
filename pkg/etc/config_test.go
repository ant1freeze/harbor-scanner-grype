package etc

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caarlos0/env/v6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// clearScannerEnv removes every SCANNER_* variable from the process environment for the duration
// of the test, so tests that call GetConfig do not depend on what happens to be set in the
// developer's (or CI's) shell. t.Setenv registers the restore; the direct os.Unsetenv makes the
// variable actually absent, which matters because caarlos0/env treats "absent" (envDefault
// applies) differently from "set to empty" (notEmpty fields reject it).
func clearScannerEnv(t *testing.T) {
	t.Helper()
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); strings.HasPrefix(k, "SCANNER_") {
			t.Setenv(k, "") // registers the restore
			os.Unsetenv(k)
		}
	}
}

func TestGetConfig(t *testing.T) {
	clearScannerEnv(t)
	// Set some test environment variables
	t.Setenv("SCANNER_LOG_LEVEL", "debug")
	t.Setenv("SCANNER_GRYPE_CACHE_DIR", "/test/cache")
	t.Setenv("SCANNER_GRYPE_SEVERITY", "High,Critical")

	config, err := GetConfig()
	assert.NoError(t, err)
	assert.Equal(t, "/test/cache", config.Grype.CacheDir)
	assert.Equal(t, "High,Critical", config.Grype.Severity)
}

func TestLogLevel(t *testing.T) {
	tests := []struct {
		envValue string
		expected slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"error", slog.LevelError},
		{"", slog.LevelInfo}, // default
	}

	for _, test := range tests {
		if test.envValue != "" {
			t.Setenv("SCANNER_LOG_LEVEL", test.envValue)
		} else {
			os.Unsetenv("SCANNER_LOG_LEVEL")
		}
		assert.Equal(t, test.expected, LogLevel())
	}
}

func TestAPIIsTLSEnabled(t *testing.T) {
	api := API{
		TLSCertificate: "",
		TLSKey:         "",
	}
	assert.False(t, api.IsTLSEnabled())

	api.TLSCertificate = "/path/to/cert"
	api.TLSKey = "/path/to/key"
	assert.True(t, api.IsTLSEnabled())
}

func TestGrypeConfigDefaults(t *testing.T) {
	var config Grype
	require.NoError(t, env.Parse(&config))

	// Test default values
	assert.Equal(t, "/home/scanner/.cache/grype", config.CacheDir)
	assert.Equal(t, "/home/scanner/.cache/reports", config.ReportsDir)
	assert.False(t, config.DebugMode)
	assert.Equal(t, "Unknown,Low,Medium,High,Critical", config.Severity)
	assert.False(t, config.IgnoreUnfixed)
	assert.False(t, config.OnlyFixed)
	assert.False(t, config.SkipUpdate)
	assert.False(t, config.OfflineScan)
	assert.False(t, config.Insecure)
	assert.Equal(t, 5*time.Minute, config.Timeout)
	assert.False(t, config.AddCPEsIfNone)
	assert.False(t, config.ByCVE)
	assert.Equal(t, "json", config.Output)
}

func TestPolicyDefaults(t *testing.T) {
	clearScannerEnv(t)
	config, err := GetConfig()
	require.NoError(t, err)
	assert.Equal(t, Policy{
		Critical:        70,
		High:            30,
		Medium:          10,
		ExploitDBFile:   "/home/scanner/.cache/exploitdb/files_exploits.csv",
		ExploitDBMaxAge: 336 * time.Hour,
	}, config.Policy)
}

func TestRiskEnvOverridesDefaults(t *testing.T) {
	clearScannerEnv(t)
	// Enabled defaults to true, so setting it "false" (rather than repeating the default "true")
	// is what proves this override is actually applied.
	t.Setenv("SCANNER_RISK_ENABLED", "false")
	t.Setenv("SCANNER_RISK_MODE", "policy")
	t.Setenv("SCANNER_RISK_HIGH", "60")
	t.Setenv("SCANNER_POLICY_HIGH", "25")

	config, err := GetConfig()
	require.NoError(t, err)
	assert.False(t, config.Risk.Risk.Enabled)
	assert.Equal(t, "policy", config.Risk.Risk.Mode)
	assert.Equal(t, 60.0, config.Risk.Risk.Thresholds.High)
	assert.Equal(t, 25.0, config.Policy.High)
}

func TestRiskModeMustBeKnown(t *testing.T) {
	clearScannerEnv(t)
	t.Setenv("SCANNER_RISK_MODE", "magic")
	_, err := GetConfig()
	assert.ErrorContains(t, err, "SCANNER_RISK_MODE")
}

func TestRiskConfigDataPolicyMode(t *testing.T) {
	assert.True(t, RiskConfigData{Enabled: true, Mode: "policy"}.PolicyMode())
	assert.False(t, RiskConfigData{Enabled: false, Mode: "policy"}.PolicyMode(), "disabled")
	assert.False(t, RiskConfigData{Enabled: true, Mode: "formula"}.PolicyMode(), "formula mode")
}

func TestPolicyThresholdsMustBeOrdered(t *testing.T) {
	clearScannerEnv(t)
	t.Setenv("SCANNER_POLICY_HIGH", "80")
	_, err := GetConfig()
	assert.ErrorContains(t, err, "SCANNER_POLICY_CRITICAL")
}

func TestPolicyThresholdsMustBeValid(t *testing.T) {
	cases := []struct {
		name    string
		env     map[string]string
		wantErr string
	}{
		{"above 100", map[string]string{"SCANNER_POLICY_CRITICAL": "150"}, "SCANNER_POLICY_"},
		{"zero medium", map[string]string{"SCANNER_POLICY_MEDIUM": "0"}, "SCANNER_POLICY_"},
		{"negative medium", map[string]string{"SCANNER_POLICY_MEDIUM": "-5"}, "SCANNER_POLICY_"},
		{"two decimals", map[string]string{"SCANNER_POLICY_HIGH": "30.05"}, "at most one decimal"},
		{"more precision than one decimal", map[string]string{"SCANNER_POLICY_HIGH": "30.00000000001"}, "at most one decimal"},
		{"not a number", map[string]string{"SCANNER_POLICY_HIGH": "NaN"}, "SCANNER_POLICY_"},
		{"equal high, medium", map[string]string{"SCANNER_POLICY_HIGH": "10"}, "SCANNER_POLICY_"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			clearScannerEnv(t)
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			_, err := GetConfig()
			assert.ErrorContains(t, err, c.wantErr)
		})
	}
}

func TestPolicyThresholdsAcceptOneDecimalAnd100(t *testing.T) {
	clearScannerEnv(t)
	t.Setenv("SCANNER_POLICY_CRITICAL", "100")
	t.Setenv("SCANNER_POLICY_HIGH", "12.5")
	t.Setenv("SCANNER_POLICY_MEDIUM", "0.1")
	config, err := GetConfig()
	require.NoError(t, err)
	assert.Equal(t, 12.5, config.Policy.High)
}

func TestPolicyHighBlankErrors(t *testing.T) {
	clearScannerEnv(t)
	t.Setenv("SCANNER_POLICY_HIGH", "")
	_, err := GetConfig()
	assert.ErrorContains(t, err, "SCANNER_POLICY_HIGH")
	assert.ErrorContains(t, err, "should not be empty")
}

func TestExploitDBMaxAgeValidation(t *testing.T) {
	t.Run("blank errors", func(t *testing.T) {
		clearScannerEnv(t)
		t.Setenv("SCANNER_EXPLOITDB_MAX_AGE", "")
		_, err := GetConfig()
		assert.ErrorContains(t, err, "SCANNER_EXPLOITDB_MAX_AGE")
		assert.ErrorContains(t, err, "should not be empty")
	})

	t.Run("negative errors", func(t *testing.T) {
		clearScannerEnv(t)
		t.Setenv("SCANNER_EXPLOITDB_MAX_AGE", "-1h")
		_, err := GetConfig()
		assert.ErrorContains(t, err, "SCANNER_EXPLOITDB_MAX_AGE")
	})

	t.Run("zero is accepted", func(t *testing.T) {
		clearScannerEnv(t)
		t.Setenv("SCANNER_EXPLOITDB_MAX_AGE", "0")
		config, err := GetConfig()
		require.NoError(t, err)
		assert.Equal(t, time.Duration(0), config.Policy.ExploitDBMaxAge)
	})
}

// skipIfAppRiskConfigExists skips a test that controls risk-config.yaml through the working
// directory: LoadRiskConfig reads /app/risk-config.yaml first, so where that file exists, as in
// the runtime image, it would be read instead of the test's own file (or its absence).
func skipIfAppRiskConfigExists(t *testing.T) {
	t.Helper()
	if _, err := os.Stat("/app/risk-config.yaml"); err == nil {
		t.Skip("/app/risk-config.yaml exists and takes precedence")
	}
}

// chdirToTempDir changes the process's working directory into a fresh temp dir for the rest of
// the test, restoring the previous directory in t.Cleanup, and returns the dir. Go 1.22 (this
// project's toolchain) has no t.Chdir. LoadRiskConfig looks at /app/risk-config.yaml first and
// falls back to the relative "risk-config.yaml", resolved against the working directory set here;
// the test is skipped where /app/risk-config.yaml exists (skipIfAppRiskConfigExists).
func chdirToTempDir(t *testing.T) string {
	t.Helper()
	skipIfAppRiskConfigExists(t)
	dir := t.TempDir()

	oldWd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() {
		assert.NoError(t, os.Chdir(oldWd))
	})
	return dir
}

// chdirToTempRiskConfig writes risk-config.yaml into a fresh temp dir and makes that dir the
// working directory for the rest of the test (see chdirToTempDir).
func chdirToTempRiskConfig(t *testing.T, yamlContent string) {
	t.Helper()
	dir := chdirToTempDir(t)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "risk-config.yaml"), []byte(yamlContent), 0644))
}

func TestRiskConfigYAMLPrecedence(t *testing.T) {
	// high uses a value distinctive from the repository's own risk-config.yaml (which also has
	// mode "formula" and high 70): otherwise this test would pass even if the temp file were
	// never actually read.
	chdirToTempRiskConfig(t, `risk:
  mode: "Formula"
  enabled: true
  thresholds: {critical: 85, high: 71.5, medium: 50, low: 0.01}
`)

	t.Run("mode is normalised from the file", func(t *testing.T) {
		clearScannerEnv(t)
		config, err := GetConfig()
		require.NoError(t, err)
		assert.Equal(t, "formula", config.Risk.Risk.Mode)
		assert.Equal(t, 71.5, config.Risk.Risk.Thresholds.High)
	})

	t.Run("SCANNER_RISK_HIGH overrides the file", func(t *testing.T) {
		clearScannerEnv(t)
		t.Setenv("SCANNER_RISK_HIGH", "60")
		config, err := GetConfig()
		require.NoError(t, err)
		assert.Equal(t, 60.0, config.Risk.Risk.Thresholds.High)
	})

	t.Run("SCANNER_RISK_MODE overrides the file", func(t *testing.T) {
		clearScannerEnv(t)
		t.Setenv("SCANNER_RISK_MODE", "policy")
		config, err := GetConfig()
		require.NoError(t, err)
		assert.Equal(t, "policy", config.Risk.Risk.Mode)
	})
}

func TestRiskConfigDisabledWithoutModeLoadsOK(t *testing.T) {
	chdirToTempRiskConfig(t, `risk:
  enabled: false
`)
	clearScannerEnv(t)
	config, err := GetConfig()
	require.NoError(t, err)
	assert.False(t, config.Risk.Risk.Enabled)
}

// A risk-config.yaml that cannot be read or parsed stops the start with an error that names the
// file: falling back to the built-in defaults would silently run in their cvss mode instead of the
// mode the file sets.
func TestBrokenRiskConfigStopsTheStart(t *testing.T) {
	t.Run("YAML syntax error", func(t *testing.T) {
		chdirToTempRiskConfig(t, "risk: {mode: [policy\n")
		clearScannerEnv(t)
		_, err := GetConfig()
		assert.ErrorContains(t, err, "risk-config.yaml")
	})

	t.Run("not readable", func(t *testing.T) {
		dir := chdirToTempDir(t)
		require.NoError(t, os.Mkdir(filepath.Join(dir, "risk-config.yaml"), 0o755))
		clearScannerEnv(t)
		_, err := GetConfig()
		assert.ErrorContains(t, err, "risk-config.yaml")
	})
}

// Without any risk-config.yaml the built-in defaults still apply.
func TestMissingRiskConfigUsesDefaults(t *testing.T) {
	chdirToTempDir(t)
	clearScannerEnv(t)
	config, err := GetConfig()
	require.NoError(t, err)
	assert.Equal(t, getDefaultRiskConfig(), config.Risk)
}

func TestRiskNumbersMustBeFinite(t *testing.T) {
	cases := []struct {
		name    string
		env     map[string]string
		wantErr string // empty means GetConfig must succeed
	}{
		{
			name: "NaN default EPSS",
			env: map[string]string{
				"SCANNER_RISK_ENABLED":      "true",
				"SCANNER_RISK_MODE":         "formula",
				"SCANNER_RISK_DEFAULT_EPSS": "NaN",
			},
			wantErr: "SCANNER_RISK_DEFAULT_EPSS",
		},
		{
			name: "+Inf high threshold",
			env: map[string]string{
				"SCANNER_RISK_ENABLED": "true",
				"SCANNER_RISK_MODE":    "formula",
				"SCANNER_RISK_HIGH":    "+Inf",
			},
			wantErr: "SCANNER_RISK_HIGH",
		},
		{
			name: "NaN ignored when risk is disabled",
			env: map[string]string{
				"SCANNER_RISK_ENABLED": "false",
				"SCANNER_RISK_HIGH":    "NaN",
			},
			wantErr: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			clearScannerEnv(t)
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			_, err := GetConfig()
			if c.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, c.wantErr)
			}
		})
	}
}
