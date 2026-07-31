package session

import (
	"os"
	"testing"

	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/config"
)

func TestSessionLifecycleV2(t *testing.T) {
	tempState, err := os.MkdirTemp("", "session_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempState)

	cfg := config.DefaultConfig()
	cfg.StateDir = tempState

	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("failed to create session manager: %v", err)
	}

	s, err := mgr.CreateSession(ModePersistent, 60, true, true)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	if s.Status != StateCreated {
		t.Errorf("expected state 'created', got '%s'", s.Status)
	}

	if err := mgr.Transition(s.ID, StateCreated, StateReady); err != nil {
		t.Errorf("Transition failed: %v", err)
	}

	retrieved, err := mgr.GetSession(s.ID)
	if err != nil || retrieved.Status != StateReady {
		t.Errorf("GetSession status mismatch: %v, status=%s", err, retrieved.Status)
	}
}

func TestSessionIDRandomness(t *testing.T) {
	id1, _ := GenerateSessionID()
	id2, _ := GenerateSessionID()

	if id1 == "" || id2 == "" || id1 == id2 {
		t.Errorf("expected non-empty distinct session IDs, got id1=%s id2=%s", id1, id2)
	}
}
