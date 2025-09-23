# Risk Calculation Feature

## Overview

This document describes the new risk calculation feature that has been added to the Harbor Scanner Grype adapter. The feature calculates vulnerability risk using the formula:

**Risk = EPSS × (CVSS/10)**

Where:
- **EPSS** (Exploit Prediction Scoring System) - probability of exploitation (0.0-1.0)
- **CVSS** (Common Vulnerability Scoring System) - severity score (0.0-10.0)

## Configuration

### Risk Configuration File

The risk calculation is configured via the `risk-config.yaml` file:

```yaml
# Risk calculation configuration
# Formula: Risk = EPSS * (CVSS/10)
# Risk percentage thresholds for severity levels

risk:
  # Risk percentage thresholds (0-100%)
  thresholds:
    critical: 75.0  # Risk >= 75% = Critical
    high: 50.0      # Risk >= 50% = High  
    medium: 25.0    # Risk >= 25% = Medium
    low: 10.0       # Risk >= 10% = Low
    # Below 10% = Unknown

  # Default values when EPSS or CVSS data is missing
  defaults:
    epss: 0.1       # Default EPSS score (10% probability)
    cvss: 5.0       # Default CVSS score (medium severity)

  # Enable/disable risk calculation
  enabled: true
```

### Default Thresholds

The system comes with the following default risk thresholds:

- **Critical**: ≥ 75%
- **High**: ≥ 50%
- **Medium**: ≥ 25%
- **Low**: ≥ 10%
- **Unknown**: < 10%

## How It Works

### 1. Data Sources

The system uses data from Grype's vulnerability database:
- **EPSS scores** from the Exploit Prediction Scoring System
- **CVSS scores** from the Common Vulnerability Scoring System (v2.0, v3.0, v3.1)

### 2. Risk Calculation Process

1. **Extract EPSS Score**: Get EPSS score from vulnerability data, use default if missing
2. **Extract CVSS Score**: Get CVSS score (prefer v3.x over v2.0), use default if missing
3. **Calculate Risk**: Apply formula `Risk = EPSS × (CVSS/10)`
4. **Convert to Percentage**: Multiply by 100 to get percentage
5. **Map to Severity**: Compare against configured thresholds

### 3. Severity Mapping

The calculated risk percentage is mapped to Harbor severity levels:

```go
if riskPercentage >= config.Thresholds.Critical {
    return harbor.SevCritical
} else if riskPercentage >= config.Thresholds.High {
    return harbor.SevHigh
} else if riskPercentage >= config.Thresholds.Medium {
    return harbor.SevMedium
} else if riskPercentage >= config.Thresholds.Low {
    return harbor.SevLow
}
return harbor.SevUnknown
```

## Examples

### Example 1: Critical Risk
- EPSS: 0.9 (90% probability)
- CVSS: 9.5 (very high severity)
- Risk = 0.9 × (9.5/10) = 0.855 = 85.5%
- Result: **Critical** (≥ 75%)

### Example 2: High Risk
- EPSS: 0.6 (60% probability)
- CVSS: 8.0 (high severity)
- Risk = 0.6 × (8.0/10) = 0.48 = 48%
- Result: **High** (≥ 50%)

### Example 3: Medium Risk
- EPSS: 0.3 (30% probability)
- CVSS: 7.0 (medium-high severity)
- Risk = 0.3 × (7.0/10) = 0.21 = 21%
- Result: **Medium** (≥ 25%)

### Example 4: Low Risk
- EPSS: 0.2 (20% probability)
- CVSS: 5.0 (medium severity)
- Risk = 0.2 × (5.0/10) = 0.1 = 10%
- Result: **Low** (≥ 10%)

### Example 5: Unknown Risk
- EPSS: 0.05 (5% probability)
- CVSS: 3.0 (low severity)
- Risk = 0.05 × (3.0/10) = 0.015 = 1.5%
- Result: **Unknown** (< 10%)

## Configuration Customization

### Customizing Thresholds

You can customize the risk thresholds by modifying the `risk-config.yaml` file:

```yaml
risk:
  thresholds:
    critical: 80.0  # More strict - only 80%+ is Critical
    high: 60.0      # More strict - only 60%+ is High
    medium: 30.0    # More strict - only 30%+ is Medium
    low: 15.0       # More strict - only 15%+ is Low
```

### Disabling Risk Calculation

To disable risk calculation and use Grype's original severity mapping:

```yaml
risk:
  enabled: false
```

### Custom Default Values

Adjust default values for missing data:

```yaml
risk:
  defaults:
    epss: 0.2       # Higher default EPSS (20% probability)
    cvss: 6.0       # Higher default CVSS (medium-high severity)
```

## Deployment

### Docker Build

The risk configuration file is automatically included in the Docker image:

```dockerfile
COPY risk-config.yaml /app/risk-config.yaml
```

### File Locations

The system looks for the configuration file in the following order:
1. `/app/risk-config.yaml` (production)
2. `risk-config.yaml` (development)

## Testing

The feature includes comprehensive tests covering:
- Risk calculation with various EPSS/CVSS combinations
- Threshold mapping
- Default value handling
- Missing data scenarios

Run tests with:
```bash
go test ./pkg/scan -v
```

## Benefits

1. **More Accurate Risk Assessment**: Combines exploit probability (EPSS) with severity (CVSS)
2. **Configurable Thresholds**: Organizations can adjust risk levels to their needs
3. **Fallback Handling**: Graceful handling of missing EPSS/CVSS data
4. **Backward Compatibility**: Can be disabled to use original Grype severity mapping
5. **Real-time Calculation**: Risk is calculated during each scan

## Monitoring

The system logs risk calculation details when debug mode is enabled:

```bash
docker run -e SCANNER_GRYPE_DEBUG_MODE=true harbor-scanner-grype:latest
```

This will show detailed information about EPSS/CVSS scores and calculated risk percentages.
