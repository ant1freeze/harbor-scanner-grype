package redisx

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/etc"
)

func NewClient(config etc.RedisPool) (*redis.Client, error) {
	opts, err := redis.ParseURL(config.URL)
	if err != nil {
		return nil, fmt.Errorf("parsing redis URL: %w", err)
	}

	opts.PoolSize = config.MaxActive
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
