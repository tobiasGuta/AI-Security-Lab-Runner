package lab

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ai-security-lab-runner/lab-runner/internal/config"
)

type MockDockerClient struct{}

func (m *MockDockerClient) CheckDockerAvailable(ctx context.Context) error  { return nil }
func (m *MockDockerClient) CheckComposeAvailable(ctx context.Context) error { return nil }
func (m *MockDockerClient) CheckLinuxContainers(ctx context.Context) error  { return nil }
func (m *MockDockerClient) BuildImage(ctx context.Context, dockerfilePath, imageTag string) error {
	return nil
}
func (m *MockDockerClient) ComposeUp(ctx context.Context, projectName, composeFilePath string) error {
	return nil
}
func (m *MockDockerClient) ComposeDown(ctx context.Context, projectName, composeFilePath string) error {
	return nil
}
func (m *MockDockerClient) ExecInRunner(ctx context.Context, projectName, composeFilePath, cwd, cmd string, env map[string]string, timeout time.Duration, maxOutputBytes int64) (exitCode int, stdout, stderr string, timedOut, truncated bool, err error) {
	return 0, "mock stdout", "", false, false, nil
}
func (m *MockDockerClient) CopyFileFromRunner(ctx context.Context, projectName, scratchContainerPath, hostDestPath string) error {
	return os.WriteFile(hostDestPath, []byte("mock export data"), 0644)
}
func (m *MockDockerClient) ListManagedResources(ctx context.Context) ([]string, error) {
	return []string{}, nil
}

func TestListProjectsAndStart(t *testing.T) {
	tempLabRoot, err := os.MkdirTemp("", "lab_root_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempLabRoot)

	tempState, err := os.MkdirTemp("", "lab_state_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempState)

	labDir := filepath.Join(tempLabRoot, "demo-lab")
	if err := os.MkdirAll(labDir, 0755); err != nil {
		t.Fatal(err)
	}

	manifestContent := `
version: 1
name: "demo-lab"
description: "Demo Lab"
targets:
  - name: "target"
    internal_port: 80
`
	if err := os.WriteFile(filepath.Join(labDir, "labrunner.yaml"), []byte(manifestContent), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.LabRoot = tempLabRoot
	cfg.StateDir = tempState

	eng, err := NewEngine(cfg, &MockDockerClient{}, nil)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	projs, err := eng.ListProjects()
	if err != nil || len(projs) != 1 {
		t.Fatalf("ListProjects failed: len=%d, err=%v", len(projs), err)
	}

	res, err := eng.StartSession(context.Background(), "demo-lab", false)
	if err != nil {
		t.Fatalf("StartSession failed: %v", err)
	}

	if res.SessionID == "" || res.Project != "demo-lab" {
		t.Errorf("StartSession result unexpected: %+v", res)
	}
}
