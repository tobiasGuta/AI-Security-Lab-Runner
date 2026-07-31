package docker

import (
	"strings"
	"testing"

	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/config"
)

func TestGenerateComposeYAMLRunnerOnly(t *testing.T) {
	cfg := config.DefaultConfig()

	yamlStr, err := GenerateComposeYAML("sess-12345", true, true, cfg)
	if err != nil {
		t.Fatalf("GenerateComposeYAML failed: %v", err)
	}

	if !strings.Contains(yamlStr, "ai.security.lab-runner.session: sess-12345") {
		t.Errorf("expected session label in generated compose")
	}

	if !strings.Contains(yamlStr, "host.docker.internal:host-gateway") {
		t.Errorf("expected host-gateway extra_hosts mapping")
	}

	if !strings.Contains(yamlStr, "read_only: true") {
		t.Errorf("expected read_only: true in runner service")
	}

	if strings.Contains(yamlStr, "workspace") {
		t.Errorf("expected NO workspace mount in generic sandbox architecture")
	}
}
