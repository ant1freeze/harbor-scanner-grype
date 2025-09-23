# Changelog

## [Unreleased] - Risk Calculation Feature

### Added
- **Risk Calculation Formula**: Implemented `Risk = EPSS × (CVSS/10)` for vulnerability severity assessment
- **Configurable Risk Thresholds**: YAML-based configuration for criticality levels
- **EPSS Support**: Integration with Exploit Prediction Scoring System data
- **CVSS Priority**: Prefer CVSS v3.x over v2.0 scores
- **Default Value Handling**: Graceful fallback for missing EPSS/CVSS data
- **Risk Configuration File**: `risk-config.yaml` with customizable thresholds
- **Comprehensive Testing**: Full test coverage for risk calculation logic

### Changed
- **Severity Mapping**: Now uses calculated risk instead of direct Grype severity
- **Transformer Interface**: Updated to accept risk configuration
- **Docker Build**: Includes risk configuration file in container image

### Configuration
- **Default Thresholds**:
  - Critical: ≥ 75%
  - High: ≥ 50%
  - Medium: ≥ 25%
  - Low: ≥ 10%
  - Unknown: < 10%
- **Default Values**:
  - EPSS: 0.1 (10% probability)
  - CVSS: 5.0 (medium severity)

### Files Modified
- `pkg/etc/config.go` - Added risk configuration structures
- `pkg/grype/model.go` - Added EPSS data structure
- `pkg/scan/transformer.go` - Implemented risk calculation logic
- `cmd/scanner-grype/main.go` - Updated transformer initialization
- `Dockerfile` - Added risk configuration file
- `go.mod` - Added yaml.v2 dependency

### Files Added
- `risk-config.yaml` - Risk calculation configuration
- `pkg/scan/transformer_test.go` - Comprehensive test suite
- `RISK_CALCULATION.md` - Detailed documentation

### Backward Compatibility
- Risk calculation can be disabled via `risk.enabled: false`
- Falls back to original Grype severity mapping when disabled
- No breaking changes to existing API
