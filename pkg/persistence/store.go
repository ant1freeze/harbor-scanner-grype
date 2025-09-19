package persistence

import (
	"context"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/harbor"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/job"
)

type Store interface {
	Create(ctx context.Context, scanJob *job.ScanJob) error
	Get(ctx context.Context, key job.ScanJobKey) (*job.ScanJob, error)
	UpdateStatus(ctx context.Context, key job.ScanJobKey, status job.Status, errorMsg string) error
	UpdateReport(ctx context.Context, key job.ScanJobKey, report *harbor.ScanReport) error
}
