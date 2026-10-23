package lab

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/session"
)

func TestTTLReaperImmediatelyCleansPersistedExpiredSession(t *testing.T) {
	client := &cleanupTestDocker{}
	engine := makeCleanupTestEngine(t, client)
	staleID := addCleanupTestSession(t, engine, true)
	healthyID := addCleanupTestSession(t, engine, false)

	ctx, cancel := context.WithCancel(context.Background())
	events := make(chan StaleCleanupResult, 2)
	done := make(chan struct{})
	go func() {
		defer close(done)
		engine.RunStaleSessionReaper(ctx, time.Hour, func(result StaleCleanupResult) {
			events <- result
		})
	}()

	select {
	case result := <-events:
		if result.SessionID != staleID || !result.Cleaned || result.Error != "" {
			t.Fatalf("wrong automatic cleanup result: %+v", result)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reaper failed to sweep stale session on start")
	}
	cancel()
	<-done
	if client.downs != 1 {
		t.Fatalf("unexpected cleanup calls: %d", client.downs)
	}
	if _, err := engine.sessMgr.GetSession(staleID); !errors.Is(err, session.ErrSessionNotFound) {
		t.Fatalf("stale state still exists after reaping: %v", err)
	}
	if _, err := engine.sessMgr.GetSession(healthyID); err != nil {
		t.Fatalf("healthy session unexpectedly removed: %v", err)
	}
}

func TestTTLReaperWaitsForRunningLeaseThenCleansUp(t *testing.T) {
	client := &cleanupTestDocker{}
	engine := makeCleanupTestEngine(t, client)
	id := addCleanupTestSession(t, engine, false)
	lease, err := engine.sessMgr.AcquireExecLease(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.sessMgr.UpdateSessionState(id, func(s *session.Session) {
		s.ExpiresAt = time.Now().Add(-time.Second)
	}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	events := make(chan StaleCleanupResult, 2)
	done := make(chan struct{})
	go func() {
		defer close(done)
		engine.RunStaleSessionReaper(ctx, 20*time.Millisecond, func(result StaleCleanupResult) {
			events <- result
		})
	}()

	// An expiry event must not kill an already-held execution lease.
	select {
	case result := <-events:
		t.Fatalf("cleanup ran while execution lease active: %+v", result)
	case <-time.After(80 * time.Millisecond):
	}
	lease()
	select {
	case result := <-events:
		if result.SessionID != id || !result.Cleaned || result.Error != "" {
			t.Fatalf("wrong cleanup result after release: %+v", result)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expired session not cleaned after active command finished")
	}
	cancel()
	<-done
	if client.downs != 1 {
		t.Fatalf("unexpected Docker cleanup count: %d", client.downs)
	}
}

func TestTTLReaperReportsFailureAndRetainsSession(t *testing.T) {
	client := &cleanupTestDocker{fail: true}
	engine := makeCleanupTestEngine(t, client)
	id := addCleanupTestSession(t, engine, true)

	ctx, cancel := context.WithCancel(context.Background())
	events := make(chan StaleCleanupResult, 2)
	done := make(chan struct{})
	go func() {
		defer close(done)
		engine.RunStaleSessionReaper(ctx, time.Hour, func(result StaleCleanupResult) {
			events <- result
		})
	}()
	select {
	case result := <-events:
		if result.SessionID != id || result.Cleaned || result.Error == "" {
			t.Fatalf("cleanup failure incorrectly reported: %+v", result)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("automatic cleanup failure did not return")
	}
	cancel()
	<-done
	s, err := engine.sessMgr.GetSession(id)
	if err != nil || s.Status != session.StateCleanupFailed {
		t.Fatalf("failed resource cleanup must persist: session=%+v err=%v", s, err)
	}
}
