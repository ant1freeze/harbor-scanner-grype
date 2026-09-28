package queue

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/etc"
	redisstore "github.com/aquasecurity/harbor-scanner-grype/pkg/persistence/redis"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/redisx"
)

// Idle workers each hold a pool connection inside BLMOVE. With a pool no larger than the number of
// workers, Harbor's scan request waited for a free connection and Harbor gave up after 5 seconds.
func TestEnqueueIsNotStarvedByWaitingWorkers(t *testing.T) {
	url := os.Getenv("SCANNER_TEST_REDIS_URL")
	if url == "" {
		t.Skip("set SCANNER_TEST_REDIS_URL=redis://localhost:16379/15 to run Redis tests")
	}
	const workers = 3
	rdb, err := redisx.NewClient(etc.RedisPool{URL: url, MaxActive: 1, MaxIdle: 1, IdleTimeout: time.Minute,
		ConnectionTimeout: time.Second, ReadTimeout: time.Second, WriteTimeout: time.Second}, workers)
	require.NoError(t, err)
	t.Cleanup(func() { _ = rdb.Close() })
	require.NoError(t, rdb.FlushDB(context.Background()).Err())

	f := fixture{rdb: rdb, namespace: "queue:" + t.Name(),
		store: redisstore.NewStore(etc.RedisStore{Namespace: "store:" + t.Name(), ScanJobTTL: time.Hour, PendingJobTTL: 24 * time.Hour}, rdb)}
	w := newTestWorker(f, &fakeController{store: f.store}, workers, time.Minute)
	w.Start(context.Background())
	t.Cleanup(w.Stop)
	time.Sleep(300 * time.Millisecond) // let every worker block in BLMOVE on the empty queue

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	started := time.Now()
	_, err = NewEnqueuer(etc.JobQueue{Namespace: f.namespace}, rdb, f.store, time.Minute).Enqueue(ctx, testScanRequest)
	require.NoError(t, err)
	require.Less(t, time.Since(started), time.Second)
}
