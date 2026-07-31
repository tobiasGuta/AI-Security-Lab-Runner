package lab

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/config"
	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/docker"
)

func skipIfDockerUnavailable(t *testing.T, cliClient *docker.CLIClient) {
	ctx := context.Background()
	if err := cliClient.CheckDockerAvailable(ctx); err != nil {
		t.Skipf("Docker daemon unavailable: %v", err)
	}
	if err := cliClient.CheckComposeAvailable(ctx); err != nil {
		t.Skipf("Docker compose unavailable: %v", err)
	}
	if err := cliClient.CheckLinuxContainers(ctx); err != nil {
		t.Skipf("Linux containers check failed: %v", err)
	}
}

func TestDockerIntegrationFullSuite(t *testing.T) {
	cliClient := docker.NewCLIClient()
	skipIfDockerUnavailable(t, cliClient)

	tempState, err := os.MkdirTemp("", "docker_int_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempState)

	cfg := config.DefaultConfig()
	cfg.StateDir = tempState
	cfg.Security.AllowExport = true

	eng, err := NewEngine(cfg, cliClient, nil)
	if err != nil {
		t.Fatalf("Failed to create engine with real Docker client: %v", err)
	}

	ctx := context.Background()

	// 1. Start Persistent Session & Validate Exact Snapshot
	startRes, err := eng.StartSession(ctx, nil, nil, 15)
	if err != nil {
		t.Fatalf("StartSession failed: %v", err)
	}
	sessID := startRes.SessionID

	sess, err := eng.sessMgr.GetSession(sessID)
	if err != nil || sess.RunnerContainerID == "" || sess.NetworkID == "" || sess.VolumeName == "" {
		t.Fatalf("Exact resource snapshot incomplete: %+v", sess)
	}

	defer func() {
		_, _ = eng.StopSession(ctx, sessID)
	}()

	// 2. Public HTTPS Request via sandbox-http
	httpRes, err := eng.HTTPRequest(ctx, HTTPRequestOptions{
		SessionID: sessID,
		Method:    "GET",
		URL:       "https://example.com/",
	})
	if err != nil || httpRes.StatusCode != 200 || !strings.Contains(httpRes.Body, "Example Domain") {
		t.Errorf("Public HTTPS request failed: err=%v, status=%d", err, httpRes.StatusCode)
	}

	// 3. Localhost Translation with Local Test Server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("local server response"))
	}))
	defer ts.Close()

	localHTTPRes, err := eng.HTTPRequest(ctx, HTTPRequestOptions{
		SessionID: sessID,
		Method:    "GET",
		URL:       ts.URL,
	})
	if err != nil || localHTTPRes.StatusCode != 200 || !strings.Contains(localHTTPRes.Body, "local server response") {
		t.Errorf("Localhost translation HTTP request failed: err=%v, res=%+v", err, localHTTPRes)
	}

	// 4. Host Translation Disabled Test (Must NOT be silently skipped)
	falseVal := false
	trueVal := true
	startDisabledRes, err := eng.StartSession(ctx, &trueVal, &falseVal, 15)
	if err != nil {
		t.Fatalf("Host translation disabled StartSession failed unexpectedly: %v", err)
	}
	sessDisabledID := startDisabledRes.SessionID
	defer func() { _, _ = eng.StopSession(ctx, sessDisabledID) }()

	if sessDisabledID == sessID {
		t.Fatalf("Session IDs must differ between sessions: main=%s, disabled=%s", sessID, sessDisabledID)
	}

	httpResHost, errHost := eng.HTTPRequest(ctx, HTTPRequestOptions{
		SessionID: sessDisabledID,
		Method:    "GET",
		URL:       "http://localhost:9999/",
	})
	if errHost == nil && (httpResHost == nil || (httpResHost.ErrorCategory != "POLICY_DENIED" && !strings.Contains(httpResHost.Body, "POLICY_DENIED"))) {
		t.Errorf("expected POLICY_DENIED for loopback URL on disabled session, got err=%v, res=%+v", errHost, httpResHost)
	}

	// 5. sandbox_exec Stdout Check & Persistent Write/Read Scratch Scope Assertion
	execCmdRes, err := eng.Exec(ctx, sessID, "echo 'EXEC_EXPECTED_STDOUT'", "/scratch", 10, nil)
	if err != nil {
		t.Fatalf("sandbox_exec failed unexpectedly: %v", err)
	}
	if execCmdRes.ExitCode != 0 || strings.TrimSpace(execCmdRes.Stdout) != "EXEC_EXPECTED_STDOUT" {
		t.Fatalf("sandbox_exec stdout empty or unexpected: exitCode=%d, stdout=%q, err=%v", execCmdRes.ExitCode, execCmdRes.Stdout, err)
	}

	testPayload := "integration test payload data"
	writeRes, err := eng.WriteFile(ctx, sessID, "/scratch/int_test.txt", testPayload, "utf-8", true)
	if err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	if writeRes.SessionID != sessID {
		t.Fatalf("WriteFile session ID mismatch: expected %s, got %s", sessID, writeRes.SessionID)
	}

	readRes, err := eng.ReadFile(ctx, sessID, "/scratch/int_test.txt", 0, 100, "utf-8")
	if err != nil || readRes.Content != testPayload {
		t.Fatalf("ReadFile failed: err=%v, content=%s", err, readRes.Content)
	}
	if readRes.SessionID != sessID {
		t.Fatalf("ReadFile session ID mismatch: expected %s, got %s", sessID, readRes.SessionID)
	}
	if writeRes.ScratchScope != readRes.ScratchScope {
		t.Fatalf("Write/Read scratch volume scope mismatch: writeScope=%s, readScope=%s", writeRes.ScratchScope, readRes.ScratchScope)
	}

	// 6. Timeout Child Termination Verification
	runRes, err := eng.Run(ctx, "sleep 10", "/scratch", 1, nil)
	if err != nil {
		t.Fatalf("Timeout execution returned unexpected infrastructure error: %v", err)
	}
	if !runRes.TimedOut && runRes.ExitCode != 124 {
		t.Errorf("expected timeout for sleep 10, got: %+v", runRes)
	}

	// 7. Symlink Rejection
	execSym, errExecSym := eng.Exec(ctx, sessID, "ln -s /etc/passwd /scratch/passwd_link", "/scratch", 10, nil)
	if errExecSym != nil || execSym.ExitCode != 0 {
		t.Fatalf("Symlink creation in container failed: err=%v, res=%+v", errExecSym, execSym)
	}
	_, errSym := eng.ReadFile(ctx, sessID, "/scratch/passwd_link", 0, 100, "utf-8")
	if errSym == nil {
		t.Errorf("expected error when reading symlink under /scratch, got nil")
	}

	// 8. Streaming Export Verification
	exportResObj, err := eng.ExportFile(ctx, sessID, "/scratch/int_test.txt", "exported_report.txt")
	if err != nil {
		t.Errorf("ExportFile failed: %v", err)
	} else {
		m, ok := exportResObj.(map[string]interface{})
		if !ok || m["export_path"] == "" || m["session_id"] != sessID {
			t.Errorf("ExportFile result invalid: %+v", exportResObj)
		}
	}

	// 9. Stop Session & Verify Absence
	stopRes, err := eng.StopSession(ctx, sessID)
	if err != nil || stopRes.Status != "stopped" {
		t.Fatalf("StopSession failed: err=%v, res=%+v", err, stopRes)
	}

	_, getErr := eng.sessMgr.GetSession(sessID)
	if getErr == nil {
		t.Errorf("expected session state to be removed after successful stop")
	}
}
