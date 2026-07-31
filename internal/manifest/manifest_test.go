package manifest

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidManifest(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "lab_manifest_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	manifestContent := `
version: 1
name: "test-lab"
description: "Test description"
workspace: "."
targets:
  - name: "target"
    build:
      context: "."
      dockerfile: "Dockerfile"
    internal_port: 3000
    environment:
      KEY: "VALUE"
host_access:
  publish: false
  bind_address: "127.0.0.1"
limits:
  target_memory: "512m"
  runner_memory: "1g"
`
	err = os.WriteFile(filepath.Join(tempDir, "labrunner.yaml"), []byte(manifestContent), 0644)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(tempDir, "Dockerfile"), []byte("FROM alpine"), 0644)

	m, err := LoadManifest(tempDir)
	if err != nil {
		t.Fatalf("expected valid manifest, got error: %v", err)
	}

	if m.Name != "test-lab" {
		t.Errorf("expected name 'test-lab', got '%s'", m.Name)
	}
}

func TestRejectsTraversalInManifest(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "lab_manifest_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	manifestContent := `
version: 1
name: "test-lab"
workspace: "../outside"
targets:
  - name: "target"
`
	err = os.WriteFile(filepath.Join(tempDir, "labrunner.yaml"), []byte(manifestContent), 0644)
	if err != nil {
		t.Fatal(err)
	}

	_, err = LoadManifest(tempDir)
	if err == nil {
		t.Fatalf("expected validation error for traversal path, got nil")
	}
}

func TestRejectsTargetNamedRunner(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "lab_manifest_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	manifestContent := `
version: 1
name: "test-lab"
targets:
  - name: "runner"
`
	err = os.WriteFile(filepath.Join(tempDir, "labrunner.yaml"), []byte(manifestContent), 0644)
	if err != nil {
		t.Fatal(err)
	}

	_, err = LoadManifest(tempDir)
	if err == nil {
		t.Fatalf("expected error when target is named 'runner', got nil")
	}
}
