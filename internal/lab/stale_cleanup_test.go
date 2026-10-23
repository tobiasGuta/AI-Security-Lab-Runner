package lab

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/config"
	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/docker"
	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/session"
)

type cleanupTestDocker struct {
	MockDockerClient
	downs int
	fail  bool
}

func (c *cleanupTestDocker) ComposeDown(ctx context.Context, projectName, composeFilePath string) error {
	c.downs++
	if c.fail {
		return errors.New("simulated Docker cleanup failure")
	}
	return nil
}

func (c *cleanupTestDocker) VerifyResourcesAbsent(ctx context.Context, projectName, sessionID string, snapshot docker.ResourceSnapshot) (bool, bool, bool, error) {
	if c.fail {
		return false, false, false, nil
	}
	return true, true, true, nil
}

func makeCleanupTestEngine(t *testing.T, client *cleanupTestDocker) *Engine {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.StateDir = t.TempDir()
	engine, err := NewEngine(cfg, client, nil)
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func addCleanupTestSession(t *testing.T, engine *Engine, expired bool) string {
	t.Helper()
	result, err := engine.StartSession(context.Background(), nil, nil, 60)
	if err != nil {
		t.Fatal(err)
	}
	if expired {
		err = engine.sessMgr.UpdateSessionState(result.SessionID, func(s *session.Session) {
			s.ExpiresAt = time.Now().Add(-time.Minute)
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return result.SessionID
}

func TestCleanupStaleSessionsDryRunAndVerifiedRemoval(t *testing.T) {
	client := &cleanupTestDocker{}
	engine := makeCleanupTestEngine(t, client)
	stale := addCleanupTestSession(t, engine, true)
	active := addCleanupTestSession(t, engine, false)

	dry := engine.CleanupStaleSessions(context.Background(), true)
	if len(dry) != 1 || dry[0].SessionID != stale || !dry[0].DryRun || dry[0].Cleaned || dry[0].Error != "" {
		t.Fatalf("unexpected dry-run result: %+v", dry)
	}
	if client.downs != 0 {
		t.Fatal("dry-run invoked Docker cleanup")
	}
	if candidates := engine.sessMgr.ListStaleSessions(time.Now().UTC()); len(candidates) != 1 || candidates[0].Status != session.StateReady {
		t.Fatalf("dry-run unexpectedly changed candidate state: %+v", candidates)
	}

	cleaned := engine.CleanupStaleSessions(context.Background(), false)
	if len(cleaned) != 1 || cleaned[0].SessionID != stale || !cleaned[0].Cleaned || cleaned[0].Error != "" {
		t.Fatalf("unexpected cleanup result: %+v", cleaned)
	}
	if !cleaned[0].Cleanup.RunnerRemoved || !cleaned[0].Cleanup.NetworkRemoved || !cleaned[0].Cleanup.ScratchRemoved || !cleaned[0].Cleanup.StateRemoved {
		t.Fatalf("cleanup summary missing verified absences: %+v", cleaned[0].Cleanup)
	}
	if client.downs != 1 {
		t.Fatalf("expected one Docker ComposeDown, got %d", client.downs)
	}
	if _, err := engine.sessMgr.GetSession(stale); !errors.Is(err, session.ErrSessionNotFound) {
		t.Fatalf("stale state should be removed, got %v", err)
	}
	if _, err := engine.sessMgr.GetSession(active); err != nil {
		t.Fatalf("active session was disturbed: %v", err)
	}
	if again := engine.CleanupStaleSessions(context.Background(), false); len(again) != 0 {
		t.Fatalf("cleanup is not idempotent: %+v", again)
	}
}

func TestCleanupStaleSessionsFailureRetainsStateAndReportsError(t *testing.T) {
	client := &cleanupTestDocker{fail: true}
	engine := makeCleanupTestEngine(t, client)
	stale := addCleanupTestSession(t, engine, true)

	results := engine.CleanupStaleSessions(context.Background(), false)
	if len(results) != 1 || results[0].SessionID != stale || results[0].Cleaned || results[0].Error == "" {
		t.Fatalf("failure must not be reported as cleaned: %+v", results)
	}
	state, err := engine.sessMgr.GetSession(stale)
	if err != nil {
		t.Fatal(err)
	}
	if state.Status != session.StateCleanupFailed || !state.CleanupRetryable {
		t.Fatalf("failed cleanup must retain retryable state: %+v", state)
	}
	if client.downs != 1 {
		t.Fatalf("expected one attempted ComposeDown, got %d", client.downs)
	}
}
