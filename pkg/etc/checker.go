package etc

import (
	"fmt"
	"os"
)

func Check(config Config) error {
	if err := checkGrypeConfig(config.Grype); err != nil {
		return fmt.Errorf("grype config: %w", err)
	}

	if err := checkAPIConfig(config.API); err != nil {
		return fmt.Errorf("api config: %w", err)
	}

	return nil
}

func checkGrypeConfig(config Grype) error {
	if config.CacheDir != "" {
		if err := os.MkdirAll(config.CacheDir, 0755); err != nil {
			return fmt.Errorf("creating cache dir: %w", err)
		}
	}

	if config.ReportsDir != "" {
		if err := os.MkdirAll(config.ReportsDir, 0755); err != nil {
			return fmt.Errorf("creating reports dir: %w", err)
		}
	}

	if config.ConfigFile != "" {
		if _, err := os.Stat(config.ConfigFile); os.IsNotExist(err) {
			return fmt.Errorf("config file does not exist: %s", config.ConfigFile)
		}
	}

	return nil
}

func checkAPIConfig(config API) error {
	if config.IsTLSEnabled() {
		if _, err := os.Stat(config.TLSCertificate); os.IsNotExist(err) {
			return fmt.Errorf("TLS certificate file does not exist: %s", config.TLSCertificate)
		}

		if _, err := os.Stat(config.TLSKey); os.IsNotExist(err) {
			return fmt.Errorf("TLS key file does not exist: %s", config.TLSKey)
		}

		for _, ca := range config.ClientCAs {
			if _, err := os.Stat(ca); os.IsNotExist(err) {
				return fmt.Errorf("client CA file does not exist: %s", ca)
			}
		}
	}

	return nil
}
