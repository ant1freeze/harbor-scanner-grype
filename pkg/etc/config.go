package etc

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math"
	"os"
	"strconv"
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
	Policy     Policy
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

// Policy configures SCANNER_RISK_MODE=policy.
type Policy struct {
	Critical      float64 `env:"SCANNER_POLICY_CRITICAL,notEmpty" envDefault:"70"`
	High          float64 `env:"SCANNER_POLICY_HIGH,notEmpty" envDefault:"30"`
	Medium        float64 `env:"SCANNER_POLICY_MEDIUM,notEmpty" envDefault:"10"`
	ExploitDBFile string  `env:"SCANNER_EXPLOITDB_FILE,notEmpty" envDefault:"/home/scanner/.cache/exploitdb/files_exploits.csv"`
	// ExploitDBMaxAge is how stale the Exploit-DB list may be before a warning; 0 turns the stale-list warning off.
	ExploitDBMaxAge time.Duration `env:"SCANNER_EXPLOITDB_MAX_AGE,notEmpty" envDefault:"336h"`
}

// validate checks the ladder thresholds: 0 < Medium < High < Critical <= 100, each with at most one
// decimal, because the risk is compared as it is shown, with one decimal (NaN fails the
// comparisons), and that ExploitDBMaxAge is not negative.
func (p Policy) validate() error {
	if !(p.Critical > p.High && p.High > p.Medium && p.Medium > 0 && p.Critical <= 100) {
		return fmt.Errorf("SCANNER_POLICY_CRITICAL > SCANNER_POLICY_HIGH > SCANNER_POLICY_MEDIUM > 0 and SCANNER_POLICY_CRITICAL <= 100 are required, got %v, %v, %v",
			p.Critical, p.High, p.Medium)
	}
	thresholds := []struct {
		name  string
		value float64
	}{
		{"SCANNER_POLICY_CRITICAL", p.Critical},
		{"SCANNER_POLICY_HIGH", p.High},
		{"SCANNER_POLICY_MEDIUM", p.Medium},
	}
	for _, t := range thresholds {
		if t.value != math.Round(t.value*10)/10 {
			return fmt.Errorf("%s must have at most one decimal, since the risk is compared with one decimal; got %v", t.name, t.value)
		}
	}
	if p.ExploitDBMaxAge < 0 {
		return fmt.Errorf("SCANNER_EXPLOITDB_MAX_AGE must not be negative, got %v", p.ExploitDBMaxAge)
	}
	return nil
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
	Mode           string         `yaml:"mode"`            // "formula", "cvss" or "policy"
	Thresholds     RiskThresholds `yaml:"thresholds"`      // Used when mode = "formula"
	CVSSThresholds CVSSThresholds `yaml:"cvss_thresholds"` // Used when mode = "cvss"
	Defaults       RiskDefaults   `yaml:"defaults"`
	Enabled        bool           `yaml:"enabled"`
}

// PolicyMode reports whether levels come from the policy rules.
func (r RiskConfigData) PolicyMode() bool { return r.Enabled && r.Mode == "policy" }

// validate normalises the mode combined from risk-config.yaml and SCANNER_RISK_* overrides, then
// checks it. When risk is disabled, the mode and the ten numbers below are never read, so neither
// is checked: a config that used to start (e.g. no mode set, or a differently-cased mode, while
// disabled) must keep starting.
func (r *RiskConfigData) validate() error {
	r.Mode = strings.ToLower(strings.TrimSpace(r.Mode))
	if !r.Enabled {
		return nil
	}
	switch r.Mode {
	case "formula", "cvss", "policy":
	default:
		return fmt.Errorf("risk mode %q (SCANNER_RISK_MODE or risk.mode in risk-config.yaml) must be formula, cvss or policy", r.Mode)
	}
	numbers := []struct {
		env   string
		yaml  string
		value float64
	}{
		{"SCANNER_RISK_CRITICAL", "risk.thresholds.critical", r.Thresholds.Critical},
		{"SCANNER_RISK_HIGH", "risk.thresholds.high", r.Thresholds.High},
		{"SCANNER_RISK_MEDIUM", "risk.thresholds.medium", r.Thresholds.Medium},
		{"SCANNER_RISK_LOW", "risk.thresholds.low", r.Thresholds.Low},
		{"SCANNER_RISK_CVSS_CRITICAL", "risk.cvss_thresholds.critical", r.CVSSThresholds.Critical},
		{"SCANNER_RISK_CVSS_HIGH", "risk.cvss_thresholds.high", r.CVSSThresholds.High},
		{"SCANNER_RISK_CVSS_MEDIUM", "risk.cvss_thresholds.medium", r.CVSSThresholds.Medium},
		{"SCANNER_RISK_CVSS_LOW", "risk.cvss_thresholds.low", r.CVSSThresholds.Low},
		{"SCANNER_RISK_DEFAULT_EPSS", "risk.defaults.epss", r.Defaults.EPSS},
		{"SCANNER_RISK_DEFAULT_CVSS", "risk.defaults.cvss", r.Defaults.CVSS},
	}
	for _, n := range numbers {
		if math.IsNaN(n.value) || math.IsInf(n.value, 0) {
			return fmt.Errorf("%s (or %s in risk-config.yaml) must be a finite number, got %v", n.env, n.yaml, n.value)
		}
	}
	return nil
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

	// Load risk configuration from YAML file. The built-in defaults apply only when there is no
	// risk-config.yaml at all: a file that cannot be read or parsed stops the start, rather than
	// silently running in the defaults' cvss mode instead of the mode it sets.
	riskConfig, err := LoadRiskConfig()
	switch {
	case errors.Is(err, fs.ErrNotExist):
		slog.Warn("No risk-config.yaml in /app or the working directory, using the built-in risk defaults")
		cfg.Risk = getDefaultRiskConfig()
	case err != nil:
		return cfg, err
	default:
		cfg.Risk = riskConfig
	}

	if err := applyRiskEnv(&cfg.Risk.Risk); err != nil {
		return cfg, err
	}
	if err := cfg.Risk.Risk.validate(); err != nil {
		return cfg, err
	}
	if err := cfg.Policy.validate(); err != nil {
		return cfg, err
	}

	return cfg, nil
}

// LoadRiskConfig reads /app/risk-config.yaml or, when that does not exist, ./risk-config.yaml.
// When neither exists, the error matches fs.ErrNotExist; any other read or parse error names the
// file.
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
		return config, err // an *fs.PathError, which names the file
	}

	if err := yaml.Unmarshal(data, &config); err != nil {
		return config, fmt.Errorf("parsing %s: %w", configPath, err)
	}
	return config, nil
}

// applyRiskEnv lets SCANNER_RISK_* variables override risk-config.yaml, as the deployed image does.
func applyRiskEnv(r *RiskConfigData) error {
	if v := strings.TrimSpace(os.Getenv("SCANNER_RISK_ENABLED")); v != "" {
		enabled, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("SCANNER_RISK_ENABLED: %w", err)
		}
		r.Enabled = enabled
	}
	if v := strings.TrimSpace(os.Getenv("SCANNER_RISK_MODE")); v != "" {
		r.Mode = v
	}
	numbers := []struct {
		name string
		dst  *float64
	}{
		{"SCANNER_RISK_CRITICAL", &r.Thresholds.Critical},
		{"SCANNER_RISK_HIGH", &r.Thresholds.High},
		{"SCANNER_RISK_MEDIUM", &r.Thresholds.Medium},
		{"SCANNER_RISK_LOW", &r.Thresholds.Low},
		{"SCANNER_RISK_CVSS_CRITICAL", &r.CVSSThresholds.Critical},
		{"SCANNER_RISK_CVSS_HIGH", &r.CVSSThresholds.High},
		{"SCANNER_RISK_CVSS_MEDIUM", &r.CVSSThresholds.Medium},
		{"SCANNER_RISK_CVSS_LOW", &r.CVSSThresholds.Low},
		{"SCANNER_RISK_DEFAULT_EPSS", &r.Defaults.EPSS},
		{"SCANNER_RISK_DEFAULT_CVSS", &r.Defaults.CVSS},
	}
	for _, n := range numbers {
		v := strings.TrimSpace(os.Getenv(n.name))
		if v == "" {
			continue
		}
		x, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return fmt.Errorf("%s: %w", n.name, err)
		}
		*n.dst = x
	}
	return nil
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
