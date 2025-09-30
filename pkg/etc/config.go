package etc

import (
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/caarlos0/env/v6"
	"gopkg.in/yaml.v2"
)

type BuildInfo struct {
	Version string
	Commit  string
	Date    string
}

type Config struct {
	API        API
	Grype      Grype
	RedisStore RedisStore
	JobQueue   JobQueue
	RedisPool  RedisPool
	Risk       RiskConfig
}

type Grype struct {
	CacheDir       string        `env:"SCANNER_GRYPE_CACHE_DIR" envDefault:"/home/scanner/.cache/grype"`
	ReportsDir     string        `env:"SCANNER_GRYPE_REPORTS_DIR" envDefault:"/home/scanner/.cache/reports"`
	DebugMode      bool          `env:"SCANNER_GRYPE_DEBUG_MODE" envDefault:"false"`
	Severity       string        `env:"SCANNER_GRYPE_SEVERITY" envDefault:"Unknown,Low,Medium,High,Critical"`
	IgnoreUnfixed  bool          `env:"SCANNER_GRYPE_IGNORE_UNFIXED" envDefault:"false"`
	OnlyFixed      bool          `env:"SCANNER_GRYPE_ONLY_FIXED" envDefault:"false"`
	SkipUpdate     bool          `env:"SCANNER_GRYPE_SKIP_UPDATE" envDefault:"false"`
	OfflineScan    bool          `env:"SCANNER_GRYPE_OFFLINE_SCAN" envDefault:"false"`
	Insecure       bool          `env:"SCANNER_GRYPE_INSECURE" envDefault:"false"`
	Timeout        time.Duration `env:"SCANNER_GRYPE_TIMEOUT" envDefault:"5m0s"`
	ConfigFile     string        `env:"SCANNER_GRYPE_CONFIG_FILE"`
	FailOnSeverity string        `env:"SCANNER_GRYPE_FAIL_ON_SEVERITY"`
	AddCPEsIfNone  bool          `env:"SCANNER_GRYPE_ADD_CPES_IF_NONE" envDefault:"false"`
	ByCVE          bool          `env:"SCANNER_GRYPE_BY_CVE" envDefault:"false"`
	Platform       string        `env:"SCANNER_GRYPE_PLATFORM"`
	Distro         string        `env:"SCANNER_GRYPE_DISTRO"`
	ExcludeAddl    string        `env:"SCANNER_GRYPE_EXCLUDE_ADDL"`
	Output         string        `env:"SCANNER_GRYPE_OUTPUT" envDefault:"json"`
}

type API struct {
	Addr           string        `env:"SCANNER_API_SERVER_ADDR" envDefault:":8090"`
	TLSCertificate string        `env:"SCANNER_API_SERVER_TLS_CERTIFICATE"`
	TLSKey         string        `env:"SCANNER_API_SERVER_TLS_KEY"`
	ClientCAs      []string      `env:"SCANNER_API_SERVER_CLIENT_CAS"`
	ReadTimeout    time.Duration `env:"SCANNER_API_SERVER_READ_TIMEOUT" envDefault:"15s"`
	WriteTimeout   time.Duration `env:"SCANNER_API_SERVER_WRITE_TIMEOUT" envDefault:"15s"`
	IdleTimeout    time.Duration `env:"SCANNER_API_SERVER_IDLE_TIMEOUT" envDefault:"60s"`
	MetricsEnabled bool          `env:"SCANNER_API_SERVER_METRICS_ENABLED" envDefault:"true"`
}

func (c *API) IsTLSEnabled() bool {
	return c.TLSCertificate != "" && c.TLSKey != ""
}

type RedisStore struct {
	Namespace  string        `env:"SCANNER_STORE_REDIS_NAMESPACE" envDefault:"harbor.scanner.grype:data-store"`
	ScanJobTTL time.Duration `env:"SCANNER_STORE_REDIS_SCAN_JOB_TTL" envDefault:"1h"`
}

type JobQueue struct {
	Namespace         string `env:"SCANNER_JOB_QUEUE_REDIS_NAMESPACE" envDefault:"harbor.scanner.grype:job-queue"`
	WorkerConcurrency int    `env:"SCANNER_JOB_QUEUE_WORKER_CONCURRENCY" envDefault:"1"`
}

type RedisPool struct {
	URL               string        `env:"SCANNER_REDIS_URL" envDefault:"redis://localhost:6379"`
	MaxActive         int           `env:"SCANNER_REDIS_POOL_MAX_ACTIVE" envDefault:"5"`
	MaxIdle           int           `env:"SCANNER_REDIS_POOL_MAX_IDLE" envDefault:"5"`
	IdleTimeout       time.Duration `env:"SCANNER_REDIS_POOL_IDLE_TIMEOUT" envDefault:"5m"`
	ConnectionTimeout time.Duration `env:"SCANNER_REDIS_POOL_CONNECTION_TIMEOUT" envDefault:"1s"`
	ReadTimeout       time.Duration `env:"SCANNER_REDIS_POOL_READ_TIMEOUT" envDefault:"1s"`
	WriteTimeout      time.Duration `env:"SCANNER_REDIS_POOL_WRITE_TIMEOUT" envDefault:"1s"`
}

func LogLevel() slog.Level {
	if value, ok := os.LookupEnv("SCANNER_LOG_LEVEL"); ok {
		switch strings.ToLower(value) {
		case "error":
			return slog.LevelError
		case "warn", "warning":
			return slog.LevelWarn
		case "info":
			return slog.LevelInfo
		case "trace", "debug":
			return slog.LevelDebug
		}
		return slog.LevelInfo
	}
	return slog.LevelInfo
}

// RiskConfig represents risk calculation configuration
type RiskConfig struct {
	Risk RiskConfigData `yaml:"risk"`
}

type RiskConfigData struct {
	Mode           string         `yaml:"mode"`            // "formula" or "cvss"
	Thresholds     RiskThresholds `yaml:"thresholds"`      // Used when mode = "formula"
	CVSSThresholds CVSSThresholds `yaml:"cvss_thresholds"` // Used when mode = "cvss"
	Defaults       RiskDefaults   `yaml:"defaults"`
	Enabled        bool           `yaml:"enabled"`
}

type RiskThresholds struct {
	Critical float64 `yaml:"critical"`
	High     float64 `yaml:"high"`
	Medium   float64 `yaml:"medium"`
	Low      float64 `yaml:"low"`
}

type CVSSThresholds struct {
	Critical float64 `yaml:"critical"`
	High     float64 `yaml:"high"`
	Medium   float64 `yaml:"medium"`
	Low      float64 `yaml:"low"`
}

type RiskDefaults struct {
	EPSS float64 `yaml:"epss"`
	CVSS float64 `yaml:"cvss"`
}

func GetConfig() (Config, error) {
	var cfg Config
	err := env.Parse(&cfg)
	if err != nil {
		return cfg, err
	}

	if _, ok := os.LookupEnv("SCANNER_GRYPE_DEBUG_MODE"); !ok {
		if LogLevel() == slog.LevelDebug {
			cfg.Grype.DebugMode = true
		}
	}

	// Load risk configuration from YAML file
	riskConfig, err := LoadRiskConfig()
	if err != nil {
		slog.Warn("Failed to load risk config, using defaults", "error", err)
		cfg.Risk = getDefaultRiskConfig()
	} else {
		cfg.Risk = riskConfig
	}

	return cfg, nil
}

func LoadRiskConfig() (RiskConfig, error) {
	var config RiskConfig

	// Try to load from risk-config.yaml
	configPath := "/app/risk-config.yaml"
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Fallback to current directory for development
		configPath = "risk-config.yaml"
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return config, err
	}

	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return config, err
	}
	return config, nil
}

func getDefaultRiskConfig() RiskConfig {
	return RiskConfig{
		Risk: RiskConfigData{
			Mode: "cvss", // Default to CVSS mode
			Thresholds: RiskThresholds{
				Critical: 75.0,
				High:     50.0,
				Medium:   25.0,
				Low:      10.0,
			},
			CVSSThresholds: CVSSThresholds{
				Critical: 9.0,
				High:     7.0,
				Medium:   4.0,
				Low:      0.1,
			},
			Defaults: RiskDefaults{
				EPSS: 0.1,
				CVSS: 5.0,
			},
			Enabled: true,
		},
	}
}
