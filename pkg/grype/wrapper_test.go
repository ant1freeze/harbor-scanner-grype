package grype

import (
	"testing"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/ext"
	"github.com/stretchr/testify/assert"
)

func TestNewWrapper(t *testing.T) {
	config := etc.Grype{
		CacheDir:   "/tmp/cache",
		ReportsDir: "/tmp/reports",
		Timeout:    30000000000, // 30 seconds
	}
	
	ambassador := ext.DefaultAmbassador()
	wrapper := NewWrapper(config, ambassador)
	
	assert.NotNil(t, wrapper)
}

func TestImageRef(t *testing.T) {
	imageRef := ImageRef{
		Name:   "alpine:latest",
		Auth:   NoAuth{},
		NonSSL: false,
	}
	
	assert.Equal(t, "alpine:latest", imageRef.Name)
	assert.False(t, imageRef.NonSSL)
}

func TestScanOption(t *testing.T) {
	opt := ScanOption{
		Format: FormatJSON,
	}
	
	assert.Equal(t, FormatJSON, opt.Format)
}

func TestRegistryAuth(t *testing.T) {
	// Test NoAuth
	noAuth := NoAuth{}
	assert.NotNil(t, noAuth)
	
	// Test BasicAuth
	basicAuth := BasicAuth{
		Username: "user",
		Password: "pass",
	}
	assert.Equal(t, "user", basicAuth.Username)
	assert.Equal(t, "pass", basicAuth.Password)
	
	// Test BearerAuth
	bearerAuth := BearerAuth{
		Token: "token123",
	}
	assert.Equal(t, "token123", bearerAuth.Token)
}
