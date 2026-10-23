package session

import (
	"testing"
	"time"

	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/config"
)

func TestListStaleSessionsFiltersAndDoesNotMutate(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.StateDir = t.TempDir()
	cfg.Limits.MaximumSessions = 20
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	type testCase struct {
		name      string
		mode      Mode
		state     State
		expired   bool
		active    int
		wantStale bool
	}
	cases := []testCase{
		{"expired ready", ModePersistent, StateReady, true, 0, true},
		{"unexpired ready", ModePersistent, StateReady, false, 0, false},
		{"cleanup failed", ModePersistent, StateCleanupFailed, false, 0, true},
		{"execution failed", ModePersistent, StateFailed, false, 0, true},
		{"already expired", ModePersistent, StateExpired, false, 0, true},
		{"expired ephemeral", ModeEphemeral, StateStarting, true, 0, true},
		{"active expired", ModePersistent, StateReady, true, 1, false},
		{"active failed", ModePersistent, StateCleanupFailed, false, 1, false},
		{"unexpired created", ModePersistent, StateCreated, false, 0, false},
		{"expired stopping", ModePersistent, StateStopping, true, 0, true},
	}
	want := make(map[string]bool)
	original := make(map[string]State)
	for _, tc := range cases {
		s, err := mgr.CreateSession(tc.mode, 60, false, false)
		if err != nil {
			t.Fatalf("%s create: %v", tc.name, err)
		}
		expires := now.Add(time.Hour)
		if tc.expired {
			expires = now.Add(-time.Hour)
		}
		if err := mgr.UpdateSessionState(s.ID, func(item *Session) {
			item.Status = tc.state
			item.ExpiresAt = expires
			item.ActiveExecCount = tc.active
		}); err != nil {
			t.Fatalf("%s update: %v", tc.name, err)
		}
		original[s.ID] = tc.state
		if tc.wantStale {
			want[s.ID] = true
		}
	}

	got := mgr.ListStaleSessions(now)
	if len(got) != len(want) {
		t.Fatalf("got %d stale sessions, want %d", len(got), len(want))
	}
	for i, session := range got {
		if !want[session.ID] {
			t.Errorf("unexpected stale session %s", session.ID)
		}
		if i > 0 && got[i-1].ID >= session.ID {
			t.Error("stale sessions are not sorted by ID")
		}
	}
	for id, state := range original {
		if mgr.sessions[id].Status != state {
			t.Errorf("dry candidate scan mutated %s: %s -> %s", id, state, mgr.sessions[id].Status)
		}
	}
}
