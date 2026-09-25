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
	os.Setenv("SCANNER_LOG_LEVEL", "debug")
	os.Setenv("SCANNER_GRYPE_CACHE_DIR", "/test/cache")
	os.Setenv("SCANNER_GRYPE_SEVERITY", "High,Critical")

	defer func() {
		os.Unsetenv("SCANNER_LOG_LEVEL")
		os.Unsetenv("SCANNER_GRYPE_CACHE_DIR")
		os.Unsetenv("SCANNER_GRYPE_SEVERITY")
	}()

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
