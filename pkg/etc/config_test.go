package etc

import (
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/caarlos0/env/v6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetConfig(t *testing.T) {
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

func TestRiskEnvOverridesFile(t *testing.T) {
	t.Setenv("SCANNER_RISK_ENABLED", "true")
	t.Setenv("SCANNER_RISK_MODE", "policy")
	t.Setenv("SCANNER_RISK_HIGH", "60")
	t.Setenv("SCANNER_POLICY_HIGH", "25")

	config, err := GetConfig()
	require.NoError(t, err)
	assert.True(t, config.Risk.Risk.Enabled)
	assert.Equal(t, "policy", config.Risk.Risk.Mode)
	assert.Equal(t, 60.0, config.Risk.Risk.Thresholds.High)
	assert.Equal(t, 25.0, config.Policy.High)
}

func TestRiskModeMustBeKnown(t *testing.T) {
	t.Setenv("SCANNER_RISK_MODE", "magic")
	_, err := GetConfig()
	assert.ErrorContains(t, err, "SCANNER_RISK_MODE")
}

func TestPolicyThresholdsMustBeOrdered(t *testing.T) {
	t.Setenv("SCANNER_POLICY_HIGH", "80")
	_, err := GetConfig()
	assert.ErrorContains(t, err, "SCANNER_POLICY_CRITICAL")
}

func TestPolicyThresholdsMustBeValid(t *testing.T) {
	cases := map[string]map[string]string{
		"above 100":          {"SCANNER_POLICY_CRITICAL": "150"},
		"zero medium":        {"SCANNER_POLICY_MEDIUM": "0"},
		"negative medium":    {"SCANNER_POLICY_MEDIUM": "-5"},
		"two decimals":       {"SCANNER_POLICY_HIGH": "30.05"},
		"not a number":       {"SCANNER_POLICY_HIGH": "NaN"},
		"equal high, medium": {"SCANNER_POLICY_HIGH": "10"},
	}
	for name, env := range cases {
		t.Run(name, func(t *testing.T) {
			for k, v := range env {
				t.Setenv(k, v)
			}
			_, err := GetConfig()
			assert.ErrorContains(t, err, "SCANNER_POLICY_")
		})
	}
}

func TestPolicyThresholdsAcceptOneDecimalAnd100(t *testing.T) {
	t.Setenv("SCANNER_POLICY_CRITICAL", "100")
	t.Setenv("SCANNER_POLICY_HIGH", "12.5")
	t.Setenv("SCANNER_POLICY_MEDIUM", "0.1")
	config, err := GetConfig()
	require.NoError(t, err)
	assert.Equal(t, 12.5, config.Policy.High)
}
