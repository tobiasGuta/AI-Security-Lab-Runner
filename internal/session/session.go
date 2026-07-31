package session

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/config"
	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/pathsafe"
)

var (
	ErrSessionNotFound        = errors.New("session not found")
	ErrInvalidStateTransition = errors.New("invalid session state transition")
	ErrSessionLimitReached    = errors.New("maximum active session limit reached")
	ErrConcurrentExecLimit    = errors.New("concurrent command execution limit reached for session")
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

type Session struct {
	ID                 string                `json:"session_id"`
	Mode               Mode                  `json:"mode"`
	ComposeProject     string                `json:"compose_project"`
	ComposeFilePath    string                `json:"compose_file_path"`
	CreatedAt          time.Time             `json:"created_at"`
	ExpiresAt          time.Time             `json:"expires_at"`
	Status             State                 `json:"status"`
	RunnerContainerID  string                `json:"runner_container_id,omitempty"`
	ScratchVolumeName  string                `json:"scratch_volume_name"`
	ActiveExecCount    int                   `json:"active_exec_count"`
	CleanupState       string                `json:"cleanup_state"`
	OutboundEnabled    bool                  `json:"outbound_enabled"`
	HostGatewayEnabled bool                  `json:"host_gateway_enabled"`
	NetworkPolicy      config.NetworkConfig  `json:"network_policy"`
	SecurityPolicy     config.SecurityConfig `json:"security_policy"`
}

type Manager struct {
	mu        sync.Mutex
	cfg       *config.Config
	sessions  map[string]*Session
	stateDir  string
	execLocks map[string]*sync.Mutex
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

	m := &Manager{
		cfg:       cfg,
		sessions:  make(map[string]*Session),
		stateDir:  sessionsDir,
		execLocks: make(map[string]*sync.Mutex),
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

	s := &Session{
		ID:                 id,
		Mode:               mode,
		ComposeProject:     composeProject,
		ComposeFilePath:    composeFile,
		CreatedAt:          now,
		ExpiresAt:          now.Add(ttl),
		Status:             StateCreated,
		ScratchVolumeName:  scratchVolName,
		CleanupState:       "none",
		OutboundEnabled:    outboundEnabled,
		HostGatewayEnabled: hostGatewayEnabled,
		NetworkPolicy:      netPolicy,
		SecurityPolicy:     m.cfg.Security,
	}

	m.sessions[id] = s
	m.execLocks[id] = &sync.Mutex{}

	if err := m.saveSessionLocked(s); err != nil {
		delete(m.sessions, id)
		delete(m.execLocks, id)
		return nil, err
	}

	return s, nil
}

func (m *Manager) GetSession(id string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	s, ok := m.sessions[id]
	if !ok {
		return nil, fmt.Errorf("%w: '%s'", ErrSessionNotFound, id)
	}

	if time.Now().UTC().After(s.ExpiresAt) && (s.Status == StateReady || s.Status == StateCreated) {
		s.Status = StateExpired
		_ = m.saveSessionLocked(s)
	}

	return s, nil
}

func (m *Manager) ListSessions() []*Session {
	m.mu.Lock()
	defer m.mu.Unlock()

	list := make([]*Session, 0, len(m.sessions))
	now := time.Now().UTC()
	for _, s := range m.sessions {
		if now.After(s.ExpiresAt) && (s.Status == StateReady || s.Status == StateCreated) {
			s.Status = StateExpired
			_ = m.saveSessionLocked(s)
		}
		list = append(list, s)
	}
	return list
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

func (m *Manager) SetActiveExecCount(id string, delta int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	s, ok := m.sessions[id]
	if !ok {
		return fmt.Errorf("%w: '%s'", ErrSessionNotFound, id)
	}

	s.ActiveExecCount += delta
	if s.ActiveExecCount < 0 {
		s.ActiveExecCount = 0
	}
	return m.saveSessionLocked(s)
}

func (m *Manager) RemoveSession(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.sessions[id]; !ok {
		return nil
	}

	sessDir := filepath.Join(m.stateDir, id)
	_ = os.RemoveAll(sessDir)

	delete(m.sessions, id)
	delete(m.execLocks, id)
	return nil
}

func (m *Manager) GetExecLock(id string) (*sync.Mutex, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	lock, ok := m.execLocks[id]
	if !ok {
		lock = &sync.Mutex{}
		m.execLocks[id] = lock
	}
	return lock, nil
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
				m.sessions[sess.ID] = &sess
				m.execLocks[sess.ID] = &sync.Mutex{}
			}
		}
	}

	return nil
}
