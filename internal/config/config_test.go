package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfigValid(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config failed validation: %v", err)
	}
}

func TestRejectsFileSystemRootAsLabRoot(t *testing.T) {
	cfg := DefaultConfig()
	if os.PathSeparator == '/' {
		cfg.LabRoot = "/"
	} else {
		cfg.LabRoot = "C:\\"
	}

	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected validation error when lab_root is root, got nil")
	}
}

func TestEnvOverride(t *testing.T) {
	tempLab, err := os.MkdirTemp("", "test_lab_root_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempLab)

	os.Setenv("LAB_RUNNER_LAB_ROOT", tempLab)
	defer os.Unsetenv("LAB_RUNNER_LAB_ROOT")

	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("failed loading config with env override: %v", err)
	}

	if filepath.Clean(cfg.LabRoot) != filepath.Clean(tempLab) {
		t.Errorf("expected lab_root %s, got %s", tempLab, cfg.LabRoot)
	}
}
