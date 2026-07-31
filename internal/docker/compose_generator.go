package docker

import (
	"fmt"

	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/config"
	"gopkg.in/yaml.v3"
)

type ComposeConfig struct {
	Services map[string]ComposeService `yaml:"services"`
	Networks map[string]ComposeNetwork `yaml:"networks"`
	Volumes  map[string]ComposeVolume  `yaml:"volumes"`
}

type ComposeService struct {
	Image       string             `yaml:"image"`
	Command     []string           `yaml:"command"`
	WorkingDir  string             `yaml:"working_dir"`
	Volumes     []ComposeVolumeRef `yaml:"volumes"`
	Networks    []string           `yaml:"networks"`
	ExtraHosts  []string           `yaml:"extra_hosts,omitempty"`
	ReadOnly    bool               `yaml:"read_only"`
	Tmpfs       []string           `yaml:"tmpfs"`
	CapDrop     []string           `yaml:"cap_drop"`
	SecurityOpt []string           `yaml:"security_opt"`
	MemLimit    string             `yaml:"mem_limit"`
	CPUs        float64            `yaml:"cpus"`
	PidsLimit   int                `yaml:"pids_limit"`
	Labels      map[string]string  `yaml:"labels"`
}

type ComposeVolumeRef struct {
	Type   string `yaml:"type"`
	Source string `yaml:"source"`
	Target string `yaml:"target"`
}

type ComposeNetwork struct {
	Internal bool              `yaml:"internal"`
	Labels   map[string]string `yaml:"labels"`
}

type ComposeVolume struct {
	Labels map[string]string `yaml:"labels"`
}

// GenerateComposeYAML builds a runner-only Docker Compose configuration.
func GenerateComposeYAML(sessID string, cfg *config.Config) (string, error) {
	labels := map[string]string{
		"ai.security.lab-runner.managed": "true",
		"ai.security.lab-runner.kind":    "sandbox-runner",
		"ai.security.lab-runner.session": sessID,
	}

	scratchVolName := fmt.Sprintf("sandbox-scratch-%s", sessID)

	var extraHosts []string
	if cfg.Network.HostGatewayEnabled {
		gwName := cfg.Network.HostGatewayName
		if gwName == "" {
			gwName = "host.docker.internal"
		}
		extraHosts = []string{fmt.Sprintf("%s:host-gateway", gwName)}
	}

	runnerSvc := ComposeService{
		Image:      cfg.Runner.Image,
		Command:    []string{"sleep", "infinity"},
		WorkingDir: "/scratch",
		Volumes: []ComposeVolumeRef{
			{
				Type:   "volume",
				Source: scratchVolName,
				Target: "/scratch",
			},
		},
		Networks:    []string{"sandbox"},
		ExtraHosts:  extraHosts,
		ReadOnly:    true,
		Tmpfs:       []string{"/tmp:rw,nosuid,nodev,size=128m"},
		CapDrop:     []string{"ALL"},
		SecurityOpt: []string{"no-new-privileges:true"},
		MemLimit:    "1g",
		CPUs:        1.0,
		PidsLimit:   256,
		Labels:      labels,
	}

	networks := map[string]ComposeNetwork{
		"sandbox": {
			Internal: !cfg.Network.OutboundEnabled,
			Labels: map[string]string{
				"ai.security.lab-runner.managed": "true",
				"ai.security.lab-runner.kind":    "sandbox-network",
				"ai.security.lab-runner.session": sessID,
			},
		},
	}

	volumes := map[string]ComposeVolume{
		scratchVolName: {
			Labels: map[string]string{
				"ai.security.lab-runner.managed": "true",
				"ai.security.lab-runner.kind":    "sandbox-scratch",
				"ai.security.lab-runner.session": sessID,
			},
		},
	}

	composeConfig := ComposeConfig{
		Services: map[string]ComposeService{
			"runner": runnerSvc,
		},
		Networks: networks,
		Volumes:  volumes,
	}

	data, err := yaml.Marshal(composeConfig)
	if err != nil {
		return "", fmt.Errorf("failed to marshal docker compose YAML: %w", err)
	}

	return string(data), nil
}
