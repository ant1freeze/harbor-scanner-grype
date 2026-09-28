package v1

import (
	"log/slog"
	"sync"
	"time"
)

const (
	// grypeInfoTTL is how long GetMetadata reuses the grype version and the DB status. The DB is
	// updated once a night, so a few minutes of delay are harmless.
	grypeInfoTTL = 5 * time.Minute
	// grypeInfoRetry is how soon a failed grype call is retried.
	grypeInfoRetry = 30 * time.Second
	// grypeInfoFirstWait bounds how long a request waits for the first grype call after start. Both
	// calls together stay well below Harbor's 5-second limit.
	grypeInfoFirstWait = time.Second
)

// cachedCall runs a slow call, a grype subprocess, in the background and keeps its last result.
// Harbor asks for the metadata on every artifact list and gives up after 5 seconds, then shows
// every artifact as unsupported. grype db status reads the 2 GB vulnerability DB and can take longer
// than that while a large image is being scanned. So requests get the last result at once, a stale
// result is refreshed by one background call at a time, and only the requests made before the first
// call has finished wait for it, at most firstWait.
type cachedCall[T any] struct {
	name      string
	call      func() (T, error)
	ttl       time.Duration // how long a result stays fresh
	retry     time.Duration // how soon a failed call is retried
	firstWait time.Duration

	mu      sync.Mutex
	value   T
	ok      bool      // value holds a result
	due     time.Time // when the next call should start; zero before the first one
	running bool

	first     chan struct{} // closed when the first call has finished
	firstDone sync.Once
}

func newCachedCall[T any](name string, call func() (T, error), ttl, retry, firstWait time.Duration) *cachedCall[T] {
	return &cachedCall[T]{name: name, call: call, ttl: ttl, retry: retry, firstWait: firstWait, first: make(chan struct{})}
}

// refreshIfDue starts a background call when the result is missing or stale and no call is running.
func (c *cachedCall[T]) refreshIfDue() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.running && !time.Now().Before(c.due) {
		c.running = true
		go c.refresh()
	}
}

// get returns the last result and whether there is one, refreshing it in the background when due.
func (c *cachedCall[T]) get() (T, bool) {
	c.refreshIfDue()
	c.mu.Lock()
	value, ok := c.value, c.ok
	c.mu.Unlock()
	if ok {
		return value, true
	}
	select {
	case <-c.first:
	case <-time.After(c.firstWait):
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.value, c.ok
}

func (c *cachedCall[T]) refresh() {
	value, err := c.call()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.running = false
	if err != nil {
		// The last result, if any, is kept: an old DB date beats none.
		slog.Warn("Failed to read the "+c.name, slog.String("err", err.Error()))
		c.due = time.Now().Add(c.retry)
	} else {
		c.value, c.ok = value, true
		c.due = time.Now().Add(c.ttl)
	}
	c.firstDone.Do(func() { close(c.first) })
}
