package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/ext"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/grype"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/http/api"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/http/api/v1"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/persistence/redis"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/queue"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/redisx"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/scan"
)

func main() {
	// Set up structured logging
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: etc.LogLevel(),
	})))

	// Load configuration
	config, err := etc.GetConfig()
	if err != nil {
		slog.Error("Failed to load configuration", slog.String("err", err.Error()))
		os.Exit(1)
	}

	// Create build info
	buildInfo := etc.BuildInfo{
		Version: "dev",
		Commit:  "none",
		Date:    "unknown",
	}

	slog.Info("Starting harbor-scanner-grype",
		slog.String("version", buildInfo.Version),
		slog.String("commit", buildInfo.Commit),
		slog.String("built_at", buildInfo.Date))

	// Create Redis client
	rdb, err := redisx.NewClient(config.RedisPool)
	if err != nil {
		slog.Error("Failed to create Redis client", slog.String("err", err.Error()))
		os.Exit(1)
	}

	// Test Redis connection
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		slog.Error("Failed to connect to Redis", slog.String("err", err.Error()))
		os.Exit(1)
	}
	slog.Info("Connected to Redis", slog.String("addr", config.RedisPool.URL))

	// Create ambassador
	ambassador := ext.DefaultAmbassador()

	// Create Grype wrapper
	grypeWrapper := grype.NewWrapper(config.Grype, ambassador)

	// Create store
	store := redis.NewStore(config.RedisStore, rdb)

	// Create transformer
	transformer := scan.NewTransformer(&scan.SystemClock{}, config.Risk)

	// Create controller
	controller := scan.NewController(store, grypeWrapper, transformer)

	// Create enqueuer
	enqueuer := queue.NewEnqueuer(config.JobQueue, rdb, store)

	// Create worker
	worker := queue.NewWorker(config.JobQueue, rdb, controller)

	// Create API handler
	handler := v1.NewAPIHandler(buildInfo, config, enqueuer, store, grypeWrapper)

	// Create HTTP server
	server, err := api.NewServer(config.API, handler)
	if err != nil {
		slog.Error("Failed to create HTTP server", slog.String("err", err.Error()))
		os.Exit(1)
	}

	// Start worker
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	worker.Start(ctx)
	slog.Info("Starting worker")

	// Start HTTP server
	slog.Info("Starting API server")
	go func() {
		if err := server.ListenAndServe(); err != nil {
			slog.Error("HTTP server error", slog.String("err", err.Error()))
			cancel()
		}
	}()

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	<-sigChan
	slog.Info("Shutdown signal received")

	// Shutdown
	worker.Stop()
	server.Shutdown()
	cancel()

	slog.Info("Harbor Scanner Grype stopped")
}
