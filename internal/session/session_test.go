package session

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ai-security-lab-runner/lab-runner/internal/config"
	"github.com/ai-security-lab-runner/lab-runner/internal/manifest"
)

func TestSessionLifecycle(t *testing.T) {
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

	mfs := &manifest.LabManifest{
		Version:   1,
		Name:      "test-lab",
		Workspace: ".",
		Dir:       filepath.Join(tempState, "labs", "test-lab"),
	}

	s, err := mgr.CreateSession(mfs)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	if s.Status != StateCreated {
		t.Errorf("expected state 'created', got '%s'", s.Status)
	}

	if err := mgr.Transition(s.ID, StateCreated, StateHealthy); err != nil {
		t.Errorf("Transition failed: %v", err)
	}

	retrieved, err := mgr.GetSession(s.ID)
	if err != nil || retrieved.Status != StateHealthy {
		t.Errorf("GetSession status mismatch: %v, status=%s", err, retrieved.Status)
	}

	// Reload manager to verify persistence
	mgr2, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("failed to create second manager: %v", err)
	}

	reloaded, err := mgr2.GetSession(s.ID)
	if err != nil || reloaded.Status != StateHealthy {
		t.Errorf("reloaded session mismatch: %v, status=%s", err, reloaded.Status)
	}
}

func TestSessionIDRandomness(t *testing.T) {
	id1, _ := GenerateSessionID()
	id2, _ := GenerateSessionID()

	if id1 == "" || id2 == "" || id1 == id2 {
		t.Errorf("expected non-empty distinct session IDs, got id1=%s id2=%s", id1, id2)
	}
}
