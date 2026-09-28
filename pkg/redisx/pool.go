package redisx

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/etc"
)

// NewClient connects to Redis. waitingWorkers is the number of queue workers: each of them holds a
// pool connection while it waits for a job in BLMOVE, so the pool gets that many connections on top
// of SCANNER_REDIS_POOL_MAX_ACTIVE. Without them, idle workers take the whole pool and Harbor's scan
// requests wait for a connection until Harbor gives up (it allows about 5 seconds).
func NewClient(config etc.RedisPool, waitingWorkers int) (*redis.Client, error) {
	opts, err := redis.ParseURL(config.URL)
	if err != nil {
		return nil, fmt.Errorf("parsing redis URL: %w", err)
	}

	opts.PoolSize = config.MaxActive + max(waitingWorkers, 0)
	opts.MinIdleConns = config.MaxIdle
	opts.ConnMaxIdleTime = config.IdleTimeout
	opts.DialTimeout = config.ConnectionTimeout
	opts.ReadTimeout = config.ReadTimeout
	opts.WriteTimeout = config.WriteTimeout

	client := redis.NewClient(opts)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("pinging redis: %w", err)
	}

	slog.Info("Connected to Redis", slog.String("addr", opts.Addr))
	return client, nil
}
