package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/harbor"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/http/api"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/job"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/persistence"
)

type Enqueuer interface {
	Enqueue(ctx context.Context, request harbor.ScanRequest) (string, error)
}

type Job struct {
	Key  job.ScanJobKey
	Args Args
}

type Args struct {
	ScanRequest *harbor.ScanRequest
}

func (j Job) ID() string {
	return j.Key.ID
}

type enqueuer struct {
	namespace string
	rdb       *redis.Client
	store     persistence.Store
}

func NewEnqueuer(config etc.JobQueue, rdb *redis.Client, store persistence.Store) Enqueuer {
	return &enqueuer{
		namespace: config.Namespace,
		rdb:       rdb,
		store:     store,
	}
}

func (e *enqueuer) Enqueue(ctx context.Context, request harbor.ScanRequest) (string, error) {
	scanJobID := uuid.New().String()

	// Determine media type and MIME type from capabilities
	var mediaType api.MediaType
	var mimeType api.MIMEType = api.MimeTypeSecurityVulnerabilityReport // default

	for _, capability := range request.Capabilities {
		if capability.Type == harbor.CapabilityTypeSBOM && capability.Parameters != nil {
			if len(capability.Parameters.SBOMMediaTypes) > 0 {
				mediaType = capability.Parameters.SBOMMediaTypes[0]
				mimeType = api.MimeTypeSecuritySBOMReport
				break
			}
		}
	}

	scanJobKey := job.ScanJobKey{
		ID:        scanJobID,
		MIMEType:  mimeType,
		MediaType: mediaType,
	}

	scanJob := &job.ScanJob{
		Key: scanJobKey,
	}

	if err := e.store.Create(ctx, scanJob); err != nil {
		return "", xerrors.Errorf("creating scan job: %w", err)
	}

	job := Job{
		Key: scanJobKey,
		Args: Args{
			ScanRequest: &request,
		},
	}

	jobData, err := json.Marshal(job)
	if err != nil {
		return "", xerrors.Errorf("marshalling job: %w", err)
	}

	channel := redisJobChannel(e.namespace)
	if err := e.rdb.Publish(ctx, channel, jobData).Err(); err != nil {
		return "", xerrors.Errorf("publishing job: %w", err)
	}

	slog.Info("Enqueued scan job",
		slog.String("scan_job_id", scanJobID),
		slog.String("channel", channel))

	return scanJobID, nil
}

func redisJobChannel(namespace string) string {
	return fmt.Sprintf("%s:jobs", namespace)
}
