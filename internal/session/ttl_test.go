package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/config"
)

func newTTLTestManager(t *testing.T) (*Manager, string) {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.StateDir = t.TempDir()
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s, err := mgr.CreateSession(ModePersistent, 60, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.Transition(s.ID, StateCreated, StateReady); err != nil {
		t.Fatal(err)
	}
	return mgr, s.ID
}

func expireTTLTestSession(t *testing.T, mgr *Manager, id string) {
	t.Helper()
	if err := mgr.UpdateSessionState(id, func(s *Session) {
		s.ExpiresAt = time.Now().UTC().Add(-time.Second)
	}); err != nil {
		t.Fatal(err)
	}
}

func TestTTLExpiredLeaseRejectedAndPersisted(t *testing.T) {
	mgr, id := newTTLTestManager(t)
	expireTTLTestSession(t, mgr, id)
	release, err := mgr.AcquireExecLease(context.Background(), id)
	if release != nil || !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("expired lease admitted: release=%v err=%v", release != nil, err)
	}
	s, err := mgr.GetSession(id)
	if err != nil {
		t.Fatal(err)
	}
	if s.Status != StateExpired || s.ActiveExecCount != 0 {
		t.Fatalf("expired session state incorrect: %+v", s)
	}
	loaded, err := NewManager(mgr.cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = loaded.AcquireExecLease(context.Background(), id)
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("expiry bypassed after state reload: %v", err)
	}
}

func TestTTLQueuedLeaseRejectedAfterDeadline(t *testing.T) {
	mgr, id := newTTLTestManager(t)
	hold, err := mgr.AcquireExecLease(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		release, err := mgr.AcquireExecLease(ctx, id)
		if release != nil {
			release()
		}
		done <- err
	}()
	// Wait until the second caller is waiting for the same session semaphore.
	deadline := time.After(2 * time.Second)
	for {
		s, err := mgr.GetSession(id)
		if err != nil {
			t.Fatal(err)
		}
		if s.ActiveExecCount == 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("queued lease never reserved")
		case <-time.After(5 * time.Millisecond):
		}
	}

	expireTTLTestSession(t, mgr, id)
	if candidates := mgr.ListStaleSessions(time.Now().UTC()); len(candidates) != 0 {
		t.Fatalf("active session selected for deletion: %+v", candidates)
	}
	hold()
	select {
	case err := <-done:
		if !errors.Is(err, ErrSessionExpired) {
			t.Fatalf("queued execution admitted after expiry: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("queued execution was not released")
	}
	s, err := mgr.GetSession(id)
	if err != nil {
		t.Fatal(err)
	}
	if s.ActiveExecCount != 0 || s.Status != StateExpired {
		t.Fatalf("lease leaked or wrong status: %+v", s)
	}
	candidates := mgr.ListStaleSessions(time.Now().UTC())
	if len(candidates) != 1 || candidates[0].ID != id {
		t.Fatalf("expired session missing from cleanup candidates: %+v", candidates)
	}
}

func TestTTLAlreadyRunningLeaseCanFinishWithoutNewAdmission(t *testing.T) {
	mgr, id := newTTLTestManager(t)
	hold, err := mgr.AcquireExecLease(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	expireTTLTestSession(t, mgr, id)
	_, err = mgr.AcquireExecLease(context.Background(), id)
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("new execution admitted past expiry: %v", err)
	}
	if stale := mgr.ListStaleSessions(time.Now().UTC()); len(stale) != 0 {
		t.Fatalf("active lease selected for cleanup: %+v", stale)
	}
	hold()
	hold()
	if stale := mgr.ListStaleSessions(time.Now().UTC()); len(stale) != 1 {
		t.Fatalf("finished expired session not eligible for cleanup: %+v", stale)
	}
	s, err := mgr.GetSession(id)
	if err != nil || s.ActiveExecCount != 0 {
		t.Fatalf("active count after release: session=%+v err=%v", s, err)
	}
}
