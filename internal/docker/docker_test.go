package docker

import (
	"strings"
	"testing"

	"github.com/ai-security-lab-runner/lab-runner/internal/config"
	"github.com/ai-security-lab-runner/lab-runner/internal/manifest"
)

func TestGenerateComposeYAML(t *testing.T) {
	cfg := config.DefaultConfig()
	m := &manifest.LabManifest{
		Version:     1,
		Name:        "test-lab",
		Description: "Test Compose Generation",
		Workspace:   ".",
		Targets: []manifest.TargetSpec{
			{
				Name:         "target",
				Image:        "nginx:alpine",
				InternalPort: 80,
				Limits: manifest.ResourceLimits{
					TargetMemory: "256m",
					TargetCPUs:   0.5,
				},
			},
		},
	}

	yamlStr, err := GenerateComposeYAML("sess-12345", m, cfg, "/labs/test-lab")
	if err != nil {
		t.Fatalf("GenerateComposeYAML failed: %v", err)
	}

	if !strings.Contains(yamlStr, "ai.security.lab-runner.session: sess-12345") {
		t.Errorf("expected session label in generated compose")
	}

	if !strings.Contains(yamlStr, "read_only: true") {
		t.Errorf("expected read_only: true in services")
	}

	if !strings.Contains(yamlStr, "internal: true") {
		t.Errorf("expected internal: true network")
	}
}
