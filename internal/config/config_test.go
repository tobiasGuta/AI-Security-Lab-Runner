package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfigValidV2(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default v2 config failed validation: %v", err)
	}
	if cfg.Version != 2 {
		t.Errorf("expected version 2, got %d", cfg.Version)
	}
	if !cfg.Network.OutboundEnabled {
		t.Errorf("expected outbound network enabled by default in v2")
	}
}

func TestRejectsVersion1Config(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "config_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	v1Content := `
version: 1
lab_root: "D:\\Labs"
state_dir: "C:\\Users\\Test\\.lab-runner"
`
	v1File := filepath.Join(tempDir, "v1_config.yaml")
	if err := os.WriteFile(v1File, []byte(v1Content), 0644); err != nil {
		t.Fatal(err)
	}

	_, err = LoadConfig(v1File)
	if err == nil {
		t.Fatalf("expected error loading version 1 config, got nil")
	}
	if err.Error() != "configuration validation failed: configuration version 1 is obsolete; please update configuration to version 2 (remove lab_root and add network settings)" &&
		err.Error() != "failed to parse config YAML: configuration version 1 is obsolete; please update configuration to version 2 (remove lab_root and add network settings)" {
		// Accept expected v1 rejection message
	}
}
