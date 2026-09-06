package lab_test

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/config"
	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/docker"
	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/lab"
)

// newHostGatewayTestServer starts a host-side test server that is reachable
// through Docker's host-gateway mapping on native Linux as well as Docker
// Desktop. The returned URL deliberately uses localhost so Lab Runner must
// still exercise its localhost -> host.docker.internal translation path.
func newHostGatewayTestServer(t *testing.T, handler http.Handler) (*httptest.Server, string) {
	t.Helper()

	listener, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("failed to create host-gateway test listener: %v", err)
	}

	server := httptest.NewUnstartedServer(handler)
	if err := server.Listener.Close(); err != nil {
		_ = listener.Close()
		t.Fatalf("failed to replace httptest listener: %v", err)
	}
	server.Listener = listener
	server.Start()

	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		server.Close()
		t.Fatalf("failed to determine host-gateway test port: %v", err)
	}

	return server, "http://localhost:" + port
}

func TestAgentFriendlyWorkflowIntegration(t *testing.T) {
	cliClient := docker.NewCLIClient()
	skipIfDockerUnavailable(t, cliClient)

	// Create test HTTP server simulating challenge web service
	server, hostGatewayURL := newHostGatewayTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/step1":
			key := r.URL.Query().Get("key")
			if key == "" {
				http.Error(w, "missing key", http.StatusBadRequest)
				return
			}
			// Set session cookie
			http.SetCookie(w, &http.Cookie{
				Name:  "auth_token",
				Value: "token_" + key,
				Path:  "/",
			})
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"step1":"ok","received_key":"` + key + `"}`))

		case "/step2":
			cookie, err := r.Cookie("auth_token")
			if err != nil || cookie.Value == "" {
				http.Error(w, "missing auth cookie", http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"step2":"success","cookie_val":"` + cookie.Value + `"}`))

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	tempState, err := os.MkdirTemp("", "agent_wf_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempState)

	cfg := config.DefaultConfig()
	cfg.StateDir = tempState
	cfg.Network.HostGatewayEnabled = true

	eng, err := lab.NewEngine(cfg, cliClient, nil)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	ctx := context.Background()

	// Step 1: Start persistent sandbox
	startRes, err := eng.StartSession(ctx, nil, nil, 15)
	if err != nil {
		t.Fatalf("StartSession failed: %v", err)
	}
	sessID := startRes.SessionID
	defer func() { _, _ = eng.StopSession(ctx, sessID) }()

	// Verify StartResult has persistent diagnostic payload
	if startRes.ExecutionMode != "persistent" || !strings.HasPrefix(startRes.RunnerInstance, "runner-") || !strings.HasPrefix(startRes.ScratchScope, "scratch-") {
		t.Errorf("StartSession diagnostic payload invalid: %+v", startRes)
	}

	// Step 2: Calculate base64url value inside Python in persistent sandbox
	calcCmd := `python3 -c "import base64; print(base64.urlsafe_b64encode(b'agent_secret_data').decode().rstrip('='))"`
	calcRes, err := eng.Exec(ctx, sessID, calcCmd, "/scratch", 10, nil)
	if err != nil || calcRes.ExitCode != 0 || calcRes.Stdout == "" {
		t.Fatalf("Sandbox Python calculation failed: err=%v, res=%+v", err, calcRes)
	}
	computedKey := strings.TrimSpace(calcRes.Stdout)
	if computedKey == "" {
		t.Fatal("Computed key from container Python execution is empty")
	}

	// Step 3: Perform structured HTTP request with calculated base64url value, saving cookies to /scratch/cookies.txt
	req1URL := hostGatewayURL + "/step1?key=" + computedKey
	httpRes1, err := eng.HTTPRequest(ctx, lab.HTTPRequestOptions{
		SessionID:       sessID,
		Method:          "GET",
		URL:             req1URL,
		SaveCookiesPath: "/scratch/cookies.txt",
	})
	if err != nil || httpRes1.StatusCode != 200 {
		t.Fatalf("HTTPRequest step1 failed: err=%v, res=%+v", err, httpRes1)
	}

	// Verify HTTP response payload returned persistent execution mode and matching session_id
	if httpRes1.ExecutionMode != "persistent" || httpRes1.SessionID != sessID {
		t.Errorf("HTTPRequest step1 returned mismatched session or execution_mode: %+v", httpRes1)
	}

	// Step 4: Perform second request loading saved cookies from /scratch/cookies.txt with same session_id
	req2URL := hostGatewayURL + "/step2"
	httpRes2, err := eng.HTTPRequest(ctx, lab.HTTPRequestOptions{
		SessionID:       sessID,
		Method:          "GET",
		URL:             req2URL,
		LoadCookiesPath: "/scratch/cookies.txt",
	})
	if err != nil || httpRes2.StatusCode != 200 || !strings.Contains(httpRes2.Body, "step2\":\"success\"") {
		t.Fatalf("HTTPRequest step2 failed with cookies: err=%v, res=%+v", err, httpRes2)
	}

	// Step 5: Write final response body to /scratch/final_response.json
	writeRes, err := eng.WriteFile(ctx, sessID, "/scratch/final_response.json", httpRes2.Body, "utf-8", true)
	if err != nil || writeRes.BytesWritten == 0 {
		t.Fatalf("WriteFile final_response.json failed: err=%v, res=%+v", err, writeRes)
	}

	// Step 6: Read final response back from persistent sandbox
	readRes, err := eng.ReadFile(ctx, sessID, "/scratch/final_response.json", 0, 1024, "utf-8")
	if err != nil || !strings.Contains(readRes.Content, "step2\":\"success\"") {
		t.Fatalf("ReadFile final_response.json failed: err=%v, res=%+v", err, readRes)
	}

	var parsedDoc struct {
		Step2     string `json:"step2"`
		CookieVal string `json:"cookie_val"`
	}
	if err := json.Unmarshal([]byte(readRes.Content), &parsedDoc); err != nil || parsedDoc.Step2 != "success" {
		t.Fatalf("Parsed content invalid: %v (content: %s)", err, readRes.Content)
	}

	// Step 7: Stop the session
	stopRes, err := eng.StopSession(ctx, sessID)
	if err != nil || stopRes.Status != "stopped" {
		t.Fatalf("StopSession failed: err=%v, res=%+v", err, stopRes)
	}
}
