package lab

import (
	"context"
	"io"
	"os"
	"testing"
	"time"

	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/config"
	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/docker"
)

type MockDockerClient struct{}

func (m *MockDockerClient) CheckDockerAvailable(ctx context.Context) error  { return nil }
func (m *MockDockerClient) CheckComposeAvailable(ctx context.Context) error { return nil }
func (m *MockDockerClient) CheckLinuxContainers(ctx context.Context) error  { return nil }
func (m *MockDockerClient) BuildImage(ctx context.Context, dockerfilePath, imageTag string) error {
	return nil
}
func (m *MockDockerClient) GetImageVersion(ctx context.Context, imageName string) (string, error) {
	return "2.0.0", nil
}
func (m *MockDockerClient) ComposeUp(ctx context.Context, projectName, composeFilePath string) (docker.ResourceSnapshot, error) {
	return docker.ResourceSnapshot{
		RunnerContainerID: "mock_c_12345",
		NetworkID:         "mock_n_12345",
		ScratchVolumeName: "mock_v_12345",
		ComposeProject:    projectName,
	}, nil
}
func (m *MockDockerClient) ComposeDown(ctx context.Context, projectName, composeFilePath string) error {
	return nil
}
func (m *MockDockerClient) InspectResources(ctx context.Context, projectName, sessionID string, snapshot docker.ResourceSnapshot) (docker.ResourceInspection, error) {
	return docker.ResourceInspection{
		Runner:        docker.ResourceState{Present: true, Identity: "mock_c_12345", OwnershipVerified: true},
		Network:       docker.ResourceState{Present: true, Identity: "mock_n_12345", OwnershipVerified: true},
		ScratchVolume: docker.ResourceState{Present: true, Identity: "mock_v_12345", OwnershipVerified: true},
	}, nil
}
func (m *MockDockerClient) ExecInRunner(ctx context.Context, projectName, composeFilePath, cwd, cmd string, env map[string]string, timeout time.Duration, maxOutputBytes int64) (exitCode int, stdout, stderr string, timedOut, truncated bool, err error) {
	return 0, `{"requested_url":"http://localhost:3000/api/info","effective_url":"http://localhost:3000/api/info","status_code":200,"headers":{"Content-Type":["application/json"]},"body":"{\"status\":\"ok\"}","duration_ms":100,"curl_exit_code":0,"host_gateway_translation":true,"connection_host":"host.docker.internal"}`, "", false, false, nil
}
func (m *MockDockerClient) ExecArgvInRunner(ctx context.Context, projectName, composeFilePath, cwd string, argv []string, env map[string]string, timeout time.Duration, maxOutputBytes int64) (exitCode int, stdout, stderr string, timedOut, truncated bool, err error) {
	return 0, `{"requested_url":"http://localhost:3000/api/info","effective_url":"http://localhost:3000/api/info","status_code":200,"headers":{"Content-Type":["application/json"]},"body":"{\"status\":\"ok\"}","duration_ms":100,"curl_exit_code":0,"host_gateway_translation":true,"connection_host":"host.docker.internal"}`, "", false, false, nil
}
func (m *MockDockerClient) ExecArgvWithInputInRunner(ctx context.Context, projectName, composeFilePath, cwd string, argv []string, stdin []byte, env map[string]string, timeout time.Duration, maxOutputBytes int64) (exitCode int, stdout, stderr string, timedOut, truncated bool, err error) {
	if len(argv) > 1 && argv[1] == "stat" {
		return 0, `{"path":"/scratch/test.txt","size":100,"is_regular":true}`, "", false, false, nil
	}
	return 0, `{"requested_url":"http://localhost:3000/api/info","effective_url":"http://localhost:3000/api/info","status_code":200,"headers":{"Content-Type":["application/json"]},"body":"{\"status\":\"ok\"}","duration_ms":100,"curl_exit_code":0,"host_gateway_translation":true,"connection_host":"host.docker.internal"}`, "", false, false, nil
}
func (m *MockDockerClient) ExecArgvWithBinaryStdoutInRunner(ctx context.Context, projectName, composeFilePath, cwd string, argv []string, stdin []byte, env map[string]string, timeout time.Duration, writer io.Writer, maxOutputBytes int64) (exitCode int, stderr string, timedOut, truncated bool, err error) {
	_, _ = writer.Write([]byte("mock export data binary stream"))
	return 0, "", false, false, nil
}
func (m *MockDockerClient) CopyFileFromRunner(ctx context.Context, projectName, scratchContainerPath, hostDestPath string) error {
	return os.WriteFile(hostDestPath, []byte("mock export data"), 0644)
}
func (m *MockDockerClient) ListManagedResources(ctx context.Context) ([]string, error) {
	return []string{}, nil
}
func (m *MockDockerClient) VerifyResourceOwnership(ctx context.Context, projectName, sessionID string, snapshot docker.ResourceSnapshot) error {
	return nil
}
func (m *MockDockerClient) VerifyResourcesAbsent(ctx context.Context, projectName, sessionID string, snapshot docker.ResourceSnapshot) (runnerRemoved, networkRemoved, scratchRemoved bool, err error) {
	return true, true, true, nil
}

func TestSandboxEngineStartAndRequest(t *testing.T) {
	tempState, err := os.MkdirTemp("", "sandbox_state_*")
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

	truePtr := true
	startRes, err := eng.StartSession(context.Background(), &truePtr, &truePtr, 60)
	if err != nil {
		t.Fatalf("StartSession failed: %v", err)
	}

	if startRes.SessionID == "" || startRes.Status != "ready" {
		t.Errorf("StartSession result unexpected: %+v", startRes)
	}

	reqRes, err := eng.HTTPRequest(context.Background(), HTTPRequestOptions{
		SessionID: startRes.SessionID,
		Method:    "GET",
		URL:       "http://localhost:3000/api/info",
	})
	if err != nil {
		t.Fatalf("HTTPRequest failed: %v", err)
	}

	if !reqRes.HostGatewayTranslation {
		t.Errorf("expected HostGatewayTranslation to be true for localhost URL")
	}
	if reqRes.ConnectionHost != "host.docker.internal" {
		t.Errorf("expected ConnectionHost to be host.docker.internal, got %s", reqRes.ConnectionHost)
	}
	if reqRes.StatusCode != 200 {
		t.Errorf("expected status code 200, got %d", reqRes.StatusCode)
	}
}
