package lab

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/audit"
	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/config"
	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/docker"
	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/session"
)

func TestMCPNetworkPolicyEscalation(t *testing.T) {
	tempState, err := os.MkdirTemp("", "adv_state_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempState)

	cfg := config.DefaultConfig()
	cfg.StateDir = tempState
	cfg.Network.OutboundEnabled = false
	cfg.Network.HostGatewayEnabled = false

	eng, err := NewEngine(cfg, &MockDockerClient{}, nil)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	trueVal := true
	falseVal := false

	// Attempt escalation when globally disabled
	_, err = eng.StartSession(context.Background(), &trueVal, &falseVal, 30)
	if err == nil || !strings.Contains(err.Error(), "POLICY_DENIED") {
		t.Errorf("expected POLICY_DENIED error when requesting outbound_network=true on globally disabled config, got: %v", err)
	}

	_, err = eng.StartSession(context.Background(), &falseVal, &trueVal, 30)
	if err == nil || !strings.Contains(err.Error(), "POLICY_DENIED") {
		t.Errorf("expected POLICY_DENIED error when requesting host_access=true on globally disabled config, got: %v", err)
	}

	// Requesting false when globally disabled should succeed
	res, err := eng.StartSession(context.Background(), &falseVal, &falseVal, 30)
	if err != nil {
		t.Fatalf("StartSession with false options failed: %v", err)
	}
	if res.Network.OutboundEnabled || res.Network.HostGatewayEnabled {
		t.Errorf("expected effective network policy to be false, got: %+v", res.Network)
	}
}

func TestMCPOptionalFieldsInheritGlobalDefaults(t *testing.T) {
	tempState, err := os.MkdirTemp("", "adv_state_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempState)

	cfg := config.DefaultConfig()
	cfg.StateDir = tempState
	cfg.Network.OutboundEnabled = true
	cfg.Network.HostGatewayEnabled = true

	eng, err := NewEngine(cfg, &MockDockerClient{}, nil)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	res, err := eng.StartSession(context.Background(), nil, nil, 30)
	if err != nil {
		t.Fatalf("StartSession with nil pointers failed: %v", err)
	}
	if !res.Network.OutboundEnabled || !res.Network.HostGatewayEnabled {
		t.Errorf("expected inherited network policy to be true, got: %+v", res.Network)
	}
}

func TestCRLFHeaderInjectionRejection(t *testing.T) {
	tempState, err := os.MkdirTemp("", "adv_state_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempState)

	cfg := config.DefaultConfig()
	cfg.StateDir = tempState

	eng, err := NewEngine(cfg, &MockDockerClient{}, nil)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	_, err = eng.HTTPRequest(context.Background(), HTTPRequestOptions{
		Method:  "GET",
		URL:     "http://example.com/",
		Headers: map[string]string{"X-Header\r\nInjected": "value"},
	})
	if err == nil || !strings.Contains(err.Error(), "invalid header name") {
		t.Errorf("expected error for CRLF in header name, got: %v", err)
	}
}

func TestAuditSecretAndPayloadLeakageScan(t *testing.T) {
	tempState, err := os.MkdirTemp("", "adv_state_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempState)

	auditLog := filepath.Join(tempState, "audit.jsonl")
	logger, err := audit.NewLogger(auditLog, true)
	if err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.StateDir = tempState

	eng, err := NewEngine(cfg, &MockDockerClient{}, logger)
	if err != nil {
		t.Fatal(err)
	}

	rawSecret := "SUPER_CONFIDENTIAL_BEARER_TOKEN_999"
	b64Secret := base64.StdEncoding.EncodeToString([]byte(rawSecret))
	hashSecret := sha256.Sum256([]byte(rawSecret))
	hexSecret := hex.EncodeToString(hashSecret[:])

	sess, err := eng.sessMgr.CreateSession(session.ModePersistent, 30, true, true)
	if err != nil {
		t.Fatal(err)
	}
	_ = eng.sessMgr.Transition(sess.ID, session.StateCreated, session.StateReady)

	// Write file with secret payload
	_, _ = eng.WriteFile(context.Background(), sess.ID, "/scratch/secret.txt", rawSecret, "utf-8", true)

	// Make HTTP request with secret header & body
	_, _ = eng.HTTPRequest(context.Background(), HTTPRequestOptions{
		SessionID: sess.ID,
		Method:    "POST",
		URL:       "http://example.com/api",
		Headers:   map[string]string{"Authorization": "Bearer " + rawSecret, "Cookie": "session=" + rawSecret},
		Body:      rawSecret,
	})

	// Inspect audit.jsonl lines
	f, err := os.Open(auditLog)
	if err != nil {
		t.Fatalf("failed to open audit log: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, rawSecret) {
			t.Errorf("SECURITY VIOLATION: raw secret found in audit log line: %s", line)
		}
		if strings.Contains(line, b64Secret) {
			t.Errorf("SECURITY VIOLATION: base64 secret found in audit log line: %s", line)
		}
		if strings.Contains(line, hexSecret) && !strings.Contains(line, "content_sha256") && !strings.Contains(line, "body_sha256") {
			t.Errorf("SECURITY VIOLATION: unexpected hex secret found in audit log line: %s", line)
		}
	}
}

func TestTransactionalCleanupFailureRecovery(t *testing.T) {
	tempState, err := os.MkdirTemp("", "adv_state_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempState)

	cfg := config.DefaultConfig()
	cfg.StateDir = tempState

	failClient := &FailingDockerClient{FailOwnership: true}
	eng, err := NewEngine(cfg, failClient, nil)
	if err != nil {
		t.Fatal(err)
	}

	startRes, err := eng.StartSession(context.Background(), nil, nil, 30)
	if err != nil {
		t.Fatal(err)
	}

	// Attempt StopSession - ownership failure should transition session to StateCleanupFailed without deleting metadata
	err = eng.StopSession(context.Background(), startRes.SessionID)
	if err == nil {
		t.Fatalf("expected StopSession to fail when ownership verification fails")
	}

	sess, err := eng.sessMgr.GetSession(startRes.SessionID)
	if err != nil {
		t.Fatalf("expected session metadata to be retained for recovery, got error: %v", err)
	}
	if sess.Status != session.StateCleanupFailed {
		t.Errorf("expected session status 'cleanup-failed', got '%s'", sess.Status)
	}
	if !sess.CleanupRetryable {
		t.Errorf("expected cleanup_retryable to be true")
	}

	// ResetSession must immediately fail if StopSession fails
	_, err = eng.ResetSession(context.Background(), startRes.SessionID)
	if err == nil {
		t.Errorf("expected ResetSession to fail when StopSession fails")
	}
}

func TestStopVsExecRaceCondition(t *testing.T) {
	tempState, err := os.MkdirTemp("", "adv_state_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempState)

	cfg := config.DefaultConfig()
	cfg.StateDir = tempState

	eng, err := NewEngine(cfg, &MockDockerClient{}, nil)
	if err != nil {
		t.Fatal(err)
	}

	startRes, err := eng.StartSession(context.Background(), nil, nil, 30)
	if err != nil {
		t.Fatal(err)
	}

	// Begin stopping session
	_ = eng.sessMgr.BeginStopping(context.Background(), startRes.SessionID)

	// Attempting Exec on stopping session MUST be rejected immediately
	_, err = eng.Exec(context.Background(), startRes.SessionID, "echo test", "/scratch", 10, nil)
	if err == nil || !strings.Contains(err.Error(), "execution lease denied") {
		t.Errorf("expected execution lease denied error when session is stopping, got: %v", err)
	}
}

type FailingDockerClient struct {
	MockDockerClient
	FailOwnership bool
}

func (f *FailingDockerClient) VerifyResourceOwnership(ctx context.Context, projectName, sessionID string, snapshot docker.ResourceSnapshot) error {
	if f.FailOwnership {
		return session.ErrSessionNotFound
	}
	return nil
}
