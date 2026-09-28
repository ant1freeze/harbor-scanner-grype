package v1

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCachedCallServesTheLastValueWhileOneRefreshRuns(t *testing.T) {
	var calls atomic.Int32
	started, release := make(chan struct{}, 1), make(chan struct{})
	c := newCachedCall("test value", func() (int32, error) {
		n := calls.Add(1)
		if n == 2 {
			started <- struct{}{}
			<-release
		}
		return n, nil
	}, time.Millisecond, time.Hour, time.Second)

	v, ok := c.get()
	require.True(t, ok)
	require.Equal(t, int32(1), v)

	time.Sleep(5 * time.Millisecond) // the value is stale now
	_, _ = c.get()
	<-started
	begin := time.Now()
	for range 20 {
		v, ok = c.get()
		require.True(t, ok)
		assert.Equal(t, int32(1), v, "the last value is served while the refresh runs")
	}
	assert.Less(t, time.Since(begin), 500*time.Millisecond, "requests must not wait for a refresh")
	assert.Equal(t, int32(2), calls.Load(), "one refresh at a time")

	close(release)
	require.Eventually(t, func() bool { v, _ := c.get(); return v >= 2 }, time.Second, time.Millisecond)
}

func TestCachedCallWaitsForTheFirstCallOnlyBriefly(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	c := newCachedCall("test value", func() (int, error) { <-release; return 1, nil }, time.Hour, time.Hour, 50*time.Millisecond)

	begin := time.Now()
	_, ok := c.get()
	assert.False(t, ok)
	assert.Less(t, time.Since(begin), time.Second)
}

func TestCachedCallKeepsTheLastValueWhenARefreshFails(t *testing.T) {
	var calls atomic.Int32
	c := newCachedCall("test value", func() (int32, error) {
		if n := calls.Add(1); n > 1 {
			return 0, errors.New("grype is busy")
		}
		return 1, nil
	}, time.Millisecond, time.Hour, time.Second)

	v, ok := c.get()
	require.True(t, ok)
	require.Equal(t, int32(1), v)

	time.Sleep(5 * time.Millisecond)
	_, _ = c.get() // starts the failing refresh
	require.Eventually(t, func() bool { return calls.Load() == 2 }, time.Second, time.Millisecond)
	time.Sleep(20 * time.Millisecond)

	v, ok = c.get()
	assert.True(t, ok)
	assert.Equal(t, int32(1), v)
	assert.Equal(t, int32(2), calls.Load(), "a failed call is retried after the retry interval, not on every request")
}

func TestCachedCallRetriesAFailedFirstCall(t *testing.T) {
	var calls atomic.Int32
	c := newCachedCall("test value", func() (int32, error) {
		if calls.Add(1) == 1 {
			return 0, errors.New("grype is busy")
		}
		return 7, nil
	}, time.Hour, time.Millisecond, time.Second)

	_, ok := c.get()
	assert.False(t, ok, "the first call failed")
	require.Eventually(t, func() bool { v, ok := c.get(); return ok && v == 7 }, time.Second, 5*time.Millisecond)
}
