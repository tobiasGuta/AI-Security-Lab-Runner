package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/config"
	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/pathsafe"
)

var (
	ErrSessionNotFound        = errors.New("session not found")
	ErrSessionExpired         = errors.New("session TTL expired")
	ErrInvalidStateTransition = errors.New("invalid session state transition")
	ErrSessionLimitReached    = errors.New("maximum active session limit reached")
	ErrConcurrentExecLimit    = errors.New("concurrent command execution limit reached")
	ErrSessionStopping        = errors.New("session is stopping or stopped, cannot execute command")
)

type Mode string

const (
	ModePersistent Mode = "persistent"
	ModeEphemeral  Mode = "ephemeral"
)

type State string

const (
	StateCreated        State = "created"
	StateStarting       State = "starting"
	StateReady          State = "ready"
	StateRunningCommand State = "running-command"
	StateStopping       State = "stopping"
	StateStopped        State = "stopped"
	StateFailed         State = "failed"
	StateCleanupFailed  State = "cleanup-failed"
	StateExpired        State = "expired"
)

type CleanupSummary struct {
	RunnerRemoved    bool   `json:"runner_removed"`
	NetworkRemoved   bool   `json:"network_removed"`
	ScratchRemoved   bool   `json:"scratch_removed"`
	StateRemoved     bool   `json:"state_removed"`
	CleanupError     string `json:"cleanup_error,omitempty"`
	CleanupRetryable bool   `json:"cleanup_retryable"`
}

type Session struct {
	ID                 string                `json:"session_id"`
	Mode               Mode                  `json:"mode"`
	ComposeProject     string                `json:"compose_project"`
	ComposeFilePath    string                `json:"compose_file_path"`
	CreatedAt          time.Time             `json:"created_at"`
	ExpiresAt          time.Time             `json:"expires_at"`
	Status             State                 `json:"status"`
	RunnerContainerID  string                `json:"runner_container_id,omitempty"`
	NetworkID          string                `json:"network_id,omitempty"`
	VolumeName         string                `json:"volume_name,omitempty"`
	ScratchVolumeName  string                `json:"scratch_volume_name"`
	ActiveExecCount    int                   `json:"active_exec_count"`
	CleanupState       string                `json:"cleanup_state"`
	CleanupError       string                `json:"cleanup_error,omitempty"`
	CleanupTimestamp   string                `json:"cleanup_timestamp,omitempty"`
	CleanupRetryable   bool                  `json:"cleanup_retryable"`
	Cleanup            CleanupSummary        `json:"cleanup_summary"`
	OutboundEnabled    bool                  `json:"outbound_enabled"`
	HostGatewayEnabled bool                  `json:"host_gateway_enabled"`
	NetworkPolicy      config.NetworkConfig  `json:"network_policy"`
	SecurityPolicy     config.SecurityConfig `json:"security_policy"`
}

type Manager struct {
	mu          sync.Mutex
	cfg         *config.Config
	sessions    map[string]*Session
	stateDir    string
	globalSem   chan struct{}
	sessionSems map[string]chan struct{}
}

func GenerateSessionID() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("failed to generate random session ID: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func NewManager(cfg *config.Config) (*Manager, error) {
	sessionsDir := filepath.Join(cfg.StateDir, "sessions")
	if err := os.MkdirAll(sessionsDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create session state dir: %w", err)
	}

	globalLimit := cfg.Limits.MaximumParallelGlobalExec
	if globalLimit <= 0 {
		globalLimit = 4
	}

	m := &Manager{
		cfg:         cfg,
		sessions:    make(map[string]*Session),
		stateDir:    sessionsDir,
		globalSem:   make(chan struct{}, globalLimit),
		sessionSems: make(map[string]chan struct{}),
	}

	if err := m.loadSavedSessions(); err != nil {
		return nil, err
	}

	return m, nil
}

func (m *Manager) CreateSession(mode Mode, ttlMinutes int, outboundEnabled, hostGatewayEnabled bool) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	activeCount := 0
	for _, s := range m.sessions {
		if s.Status == StateStarting || s.Status == StateReady || s.Status == StateRunningCommand {
			activeCount++
		}
	}

	if activeCount >= m.cfg.Limits.MaximumSessions {
		return nil, fmt.Errorf("%w: active count %d >= limit %d", ErrSessionLimitReached, activeCount, m.cfg.Limits.MaximumSessions)
	}

	id, err := GenerateSessionID()
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	if ttlMinutes <= 0 {
		ttlMinutes = m.cfg.Limits.DefaultSessionTTLMinutes
	}
	if ttlMinutes > m.cfg.Limits.MaximumSessionTTLMinutes {
		ttlMinutes = m.cfg.Limits.MaximumSessionTTLMinutes
	}
	ttl := time.Duration(ttlMinutes) * time.Minute

	sessDir := filepath.Join(m.stateDir, id)
	if err := os.MkdirAll(sessDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create session dir: %w", err)
	}

	composeFile := filepath.Join(sessDir, "docker-compose.yaml")
	composeProject := fmt.Sprintf("sandbox_%s", id[:8])
	scratchVolName := fmt.Sprintf("sandbox-scratch-%s", id)

	netPolicy := m.cfg.Network
	netPolicy.OutboundEnabled = outboundEnabled
	netPolicy.HostGatewayEnabled = hostGatewayEnabled

	sessLimit := m.cfg.Limits.MaximumParallelExecPerSession
	if sessLimit <= 0 {
		sessLimit = 1
	}

	s := &Session{
		ID:                 id,
		Mode:               mode,
		ComposeProject:     composeProject,
		ComposeFilePath:    composeFile,
		CreatedAt:          now,
		ExpiresAt:          now.Add(ttl),
		Status:             StateCreated,
		ScratchVolumeName:  scratchVolName,
		VolumeName:         scratchVolName,
		CleanupState:       "none",
		CleanupRetryable:   true,
		OutboundEnabled:    outboundEnabled,
		HostGatewayEnabled: hostGatewayEnabled,
		NetworkPolicy:      netPolicy,
		SecurityPolicy:     m.cfg.Security,
	}

	m.sessions[id] = s
	m.sessionSems[id] = make(chan struct{}, sessLimit)

	if err := m.saveSessionLocked(s); err != nil {
		delete(m.sessions, id)
		delete(m.sessionSems, id)
		return nil, err
	}

	return s, nil
}

// expireSessionLocked records expiry while holding m.mu. Expiry is checked
// against the clock, not only against a previously observed session status.
func (m *Manager) expireSessionLocked(sess *Session, now time.Time) bool {
	if sess.ExpiresAt.IsZero() || now.Before(sess.ExpiresAt) {
		return false
	}
	switch sess.Status {
	case StateCreated, StateStarting, StateReady, StateRunningCommand:
		sess.Status = StateExpired
		_ = m.saveSessionLocked(sess)
	}
	return true
}

// AcquireExecLease checks TTL both before reserving a slot and after
// acquiring semaphores: a request queued before expiry may not execute
// once the deadline has passed. Existing in-flight leases may finish.
func (m *Manager) AcquireExecLease(ctx context.Context, id string) (func(), error) {
	m.mu.Lock()
	sess, ok := m.sessions[id]
	if !ok {
		m.mu.Unlock()
		return nil, fmt.Errorf("%w: '%s'", ErrSessionNotFound, id)
	}
	if m.expireSessionLocked(sess, time.Now().UTC()) {
		m.mu.Unlock()
		return nil, fmt.Errorf("%w: session '%s'", ErrSessionExpired, id)
	}
	if sess.Status != StateReady && sess.Status != StateRunningCommand {
		m.mu.Unlock()
		return nil, fmt.Errorf("%w: session '%s' is in state '%s'", ErrSessionStopping, id, sess.Status)
	}

	sessSem, ok := m.sessionSems[id]
	if !ok {
		sessLimit := m.cfg.Limits.MaximumParallelExecPerSession
		if sessLimit <= 0 {
			sessLimit = 1
		}
		sessSem = make(chan struct{}, sessLimit)
		m.sessionSems[id] = sessSem
	}

	sess.ActiveExecCount++
	_ = m.saveSessionLocked(sess)
	m.mu.Unlock()

	// Reserve global and per-session slots, observing cancellation.
	select {
	case m.globalSem <- struct{}{}:
	case <-ctx.Done():
		m.decrementExecCount(id)
		return nil, ctx.Err()
	}

	select {
	case sessSem <- struct{}{}:
	case <-ctx.Done():
		<-m.globalSem
		m.decrementExecCount(id)
		return nil, ctx.Err()
	}

	// The request may have waited for a slot until after TTL expiry, or a
	// concurrent stop may have transitioned it out of the ready state.
	m.mu.Lock()
	current, exists := m.sessions[id]
	var admissionErr error
	switch {
	case !exists:
		admissionErr = fmt.Errorf("%w: '%s'", ErrSessionNotFound, id)
	case m.expireSessionLocked(current, time.Now().UTC()):
		admissionErr = fmt.Errorf("%w: session '%s'", ErrSessionExpired, id)
	case current.Status != StateReady && current.Status != StateRunningCommand:
		admissionErr = fmt.Errorf("%w: session '%s' is in state '%s'", ErrSessionStopping, id, current.Status)
	}
	if admissionErr != nil && exists {
		current.ActiveExecCount--
		_ = m.saveSessionLocked(current)
	}
	m.mu.Unlock()
	if admissionErr != nil {
		<-sessSem
		<-m.globalSem
		return nil, admissionErr
	}

	var once sync.Once
	release := func() {
		once.Do(func() {
			<-sessSem
			<-m.globalSem
			m.decrementExecCount(id)
		})
	}
	return release, nil
}

func (m *Manager) decrementExecCount(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if sess, ok := m.sessions[id]; ok {
		sess.ActiveExecCount--
		if sess.ActiveExecCount < 0 {
			sess.ActiveExecCount = 0
		}
		_ = m.saveSessionLocked(sess)
	}
}

// BeginStopping transitions session status to StateStopping and waits for active execs to complete.
func (m *Manager) BeginStopping(ctx context.Context, id string) error {
	m.mu.Lock()
	sess, ok := m.sessions[id]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("%w: '%s'", ErrSessionNotFound, id)
	}

	sess.Status = StateStopping
	_ = m.saveSessionLocked(sess)
	m.mu.Unlock()

	// Wait for active executions to reach zero
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		m.mu.Lock()
		active := sess.ActiveExecCount
		m.mu.Unlock()

		if active == 0 {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (m *Manager) GetSession(id string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	s, ok := m.sessions[id]
	if !ok {
		return nil, fmt.Errorf("%w: '%s'", ErrSessionNotFound, id)
	}

	m.expireSessionLocked(s, time.Now().UTC())

	cp := *s
	return &cp, nil
}

func (m *Manager) UpdateSessionState(id string, updateFn func(s *Session)) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	s, ok := m.sessions[id]
	if !ok {
		return fmt.Errorf("%w: '%s'", ErrSessionNotFound, id)
	}

	updateFn(s)
	return m.saveSessionLocked(s)
}

func (m *Manager) ListSessions() []Session {
	m.mu.Lock()
	defer m.mu.Unlock()

	list := make([]Session, 0, len(m.sessions))
	now := time.Now().UTC()
	for _, s := range m.sessions {
		if s.Mode == ModeEphemeral {
			continue // Ephemeral sessions are internal transient sessions
		}
		m.expireSessionLocked(s, now)
		list = append(list, *s)
	}
	return list
}

// ListStaleSessions snapshots candidates for explicit cleanup. It does not
// mutate session state or remove Docker resources (including in dry-run mode).
// Both persistent and interrupted ephemeral sessions can be reclaimed.
func (m *Manager) ListStaleSessions(now time.Time) []Session {
	m.mu.Lock()
	defer m.mu.Unlock()

	var candidates []Session
	for _, s := range m.sessions {
		// Never select a session with an active execution lease.
		if s.ActiveExecCount != 0 {
			continue
		}
		expired := !s.ExpiresAt.IsZero() && !now.Before(s.ExpiresAt)
		retryable := s.Status == StateExpired || s.Status == StateFailed || s.Status == StateCleanupFailed
		if !expired && !retryable {
			continue
		}
		candidates = append(candidates, *s)
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].ID < candidates[j].ID
	})
	return candidates
}

func (m *Manager) Transition(id string, from, to State) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	s, ok := m.sessions[id]
	if !ok {
		return fmt.Errorf("%w: '%s'", ErrSessionNotFound, id)
	}

	if from != "" && s.Status != from {
		return fmt.Errorf("%w: session %s is in state %s, expected %s", ErrInvalidStateTransition, id, s.Status, from)
	}

	s.Status = to
	return m.saveSessionLocked(s)
}

// RemoveSession is transactional: returns error if active executions exist or state dir deletion fails.
func (m *Manager) RemoveSession(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	sess, ok := m.sessions[id]
	if !ok {
		return nil
	}

	if sess.ActiveExecCount > 0 {
		return fmt.Errorf("cannot remove session %s while %d active executions exist", id, sess.ActiveExecCount)
	}

	sessDir := filepath.Join(m.stateDir, id)
	if err := os.RemoveAll(sessDir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete session state directory: %w", err)
	}

	delete(m.sessions, id)
	delete(m.sessionSems, id)
	return nil
}

func (m *Manager) saveSessionLocked(s *Session) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal session state: %w", err)
	}

	sessDir := filepath.Join(m.stateDir, s.ID)
	_ = os.MkdirAll(sessDir, 0700)
	metaFile := filepath.Join(sessDir, "session.json")
	tmpFile := metaFile + ".tmp"

	if err := os.WriteFile(tmpFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write session metadata: %w", err)
	}

	if err := os.Rename(tmpFile, metaFile); err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("failed to rename session file atomically: %w", err)
	}

	return nil
}

func (m *Manager) loadSavedSessions() error {
	entries, err := os.ReadDir(m.stateDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}

	sessLimit := m.cfg.Limits.MaximumParallelExecPerSession
	if sessLimit <= 0 {
		sessLimit = 1
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		id := entry.Name()
		metaFile := filepath.Join(m.stateDir, id, "session.json")
		data, err := os.ReadFile(metaFile)
		if err != nil {
			continue
		}

		var sess Session
		if err := json.Unmarshal(data, &sess); err == nil && sess.ID != "" {
			cleanID, err := pathsafe.CleanHostPath(sess.ID)
			if err == nil && cleanID == sess.ID {
				// Execution leases are process-local and cannot survive a
				// controller restart. Never resume an interrupted session
				// as if its previous commands were known to have finished.
				// This requires a single controller owner per state dir.
				if sess.ActiveExecCount != 0 {
					sess.ActiveExecCount = 0
					switch sess.Status {
					case StateCreated, StateStarting, StateReady, StateRunningCommand:
						sess.Status = StateFailed
						sess.CleanupError = "interrupted execution lease recovered at startup"
						sess.CleanupRetryable = true
					}
					if err := m.saveSessionLocked(&sess); err != nil {
						return fmt.Errorf("failed to persist interrupted session %s: %w", sess.ID, err)
					}
				}
				m.sessions[sess.ID] = &sess
				m.sessionSems[sess.ID] = make(chan struct{}, sessLimit)
			}
		}
	}

	return nil
}
