package queue

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/scan"
)

type Worker interface {
	Start(ctx context.Context)
	Stop()
}

type worker struct {
	namespace   string
	concurrency int

	rdb    *redis.Client
	pubsub *redis.PubSub

	controller scan.Controller
}

func NewWorker(config etc.JobQueue, rdb *redis.Client, controller scan.Controller) Worker {
	return &worker{
		namespace:   config.Namespace,
		concurrency: config.WorkerConcurrency,

		rdb: rdb,

		controller: controller,
	}
}

func (w *worker) Start(ctx context.Context) {
	channel := w.redisJobChannel()
	slog.Info("Starting worker", 
		slog.String("channel", channel),
		slog.Int("concurrency", w.concurrency),
	)
	
	w.pubsub = w.rdb.Subscribe(ctx, channel)
	
	ch := w.pubsub.Channel()
	slog.Info("Successfully subscribed to Redis channel", slog.String("channel", channel))

	for i := 0; i < w.concurrency; i++ {
		go func() {
			w.subscribe(ctx, ch)
		}()
	}
}

func (w *worker) Stop() {
	slog.Debug("Job queue shutdown started")
	_ = w.pubsub.Close()
	slog.Debug("Job queue shutdown completed")
}

func (w *worker) redisJobChannel() string {
	return redisJobChannel(w.namespace)
}

func (w *worker) subscribe(ctx context.Context, ch <-chan *redis.Message) {
	slog.Info("Worker goroutine started, waiting for messages")
	for msg := range ch {
		chLog := slog.With(
			slog.String("channel", msg.Channel),
			slog.String("payload", msg.Payload),
		)
		chLog.Info("Message received from Redis channel")

		if err := w.scanArtifact(ctx, msg); err != nil {
			chLog.Error("Failed to scan artifact", slog.String("err", err.Error()))
			continue
		}
	}
	slog.Info("Worker goroutine finished")
}

func (w *worker) scanArtifact(ctx context.Context, msg *redis.Message) error {
	var job Job
	if err := json.Unmarshal([]byte(msg.Payload), &job); err != nil {
		return xerrors.Errorf("unmarshalling scan request: %w", err)
	}

	// Lock the job so that other workers won't process it.
	nx, err := w.rdb.SetNX(ctx, redisLockKey(w.namespace, job.ID()), "", 5*time.Minute).Result()
	if err != nil {
		return xerrors.Errorf("redis lock: %w", err)
	} else if !nx {
		slog.Debug("Skip the locked job", slog.String("scan_job_id", job.Key.ID))
		return nil
	}

	slog.Debug("Executing enqueued scan job", slog.String("scan_job_id", job.Key.ID))
	return w.controller.Scan(ctx, job.Key, job.Args.ScanRequest)
}

func redisLockKey(namespace, jobID string) string {
	return redisJobChannel(namespace) + ":lock:" + jobID
}
