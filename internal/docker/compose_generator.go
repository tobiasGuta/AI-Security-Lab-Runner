package docker

import (
	"fmt"
	"path/filepath"

	"github.com/ai-security-lab-runner/lab-runner/internal/config"
	"github.com/ai-security-lab-runner/lab-runner/internal/manifest"
	"gopkg.in/yaml.v3"
)

type ComposeConfig struct {
	Version  string                    `yaml:"version"`
	Services map[string]ComposeService `yaml:"services"`
	Networks map[string]ComposeNetwork `yaml:"networks"`
	Volumes  map[string]ComposeVolume  `yaml:"volumes"`
}

type ComposeService struct {
	Image       string             `yaml:"image,omitempty"`
	Build       *ComposeBuild      `yaml:"build,omitempty"`
	Command     []string           `yaml:"command,omitempty"`
	WorkingDir  string             `yaml:"working_dir,omitempty"`
	Volumes     []ComposeVolumeRef `yaml:"volumes,omitempty"`
	Networks    []string           `yaml:"networks"`
	ReadOnly    bool               `yaml:"read_only"`
	Tmpfs       []string           `yaml:"tmpfs,omitempty"`
	CapDrop     []string           `yaml:"cap_drop"`
	SecurityOpt []string           `yaml:"security_opt"`
	MemLimit    string             `yaml:"mem_limit,omitempty"`
	CPUs        float64            `yaml:"cpus,omitempty"`
	PidsLimit   int                `yaml:"pids_limit,omitempty"`
	DependsOn   []string           `yaml:"depends_on,omitempty"`
	Labels      map[string]string  `yaml:"labels"`
	Ports       []string           `yaml:"ports,omitempty"`
	Environment map[string]string  `yaml:"environment,omitempty"`
}

type ComposeBuild struct {
	Context    string `yaml:"context"`
	Dockerfile string `yaml:"dockerfile"`
}

type ComposeVolumeRef struct {
	Type     string `yaml:"type"`
	Source   string `yaml:"source"`
	Target   string `yaml:"target"`
	ReadOnly bool   `yaml:"read_only,omitempty"`
}

type ComposeNetwork struct {
	Internal bool              `yaml:"internal"`
	Labels   map[string]string `yaml:"labels"`
}

type ComposeVolume struct {
	Labels map[string]string `yaml:"labels"`
}

// GenerateComposeYAML builds the Docker Compose specification for a session.
func GenerateComposeYAML(sessID string, m *manifest.LabManifest, cfg *config.Config, labDir string) (string, error) {
	labels := map[string]string{
		"ai.security.lab-runner.managed": "true",
		"ai.security.lab-runner.session": sessID,
	}

	services := make(map[string]ComposeService)
	targetNames := make([]string, 0)

	// Target services
	for _, target := range m.Targets {
		targetNames = append(targetNames, target.Name)

		memLimit := target.Limits.TargetMemory
		if memLimit == "" {
			memLimit = m.Limits.TargetMemory
		}
		if memLimit == "" {
			memLimit = "512m"
		}

		cpus := target.Limits.TargetCPUs
		if cpus == 0 {
			cpus = m.Limits.TargetCPUs
		}
		if cpus == 0 {
			cpus = 0.75
		}

		pids := target.Limits.TargetPIDs
		if pids == 0 {
			pids = m.Limits.TargetPIDs
		}
		if pids == 0 {
			pids = 128
		}

		svc := ComposeService{
			Networks: []string{"lab"},
			ReadOnly: true,
			Tmpfs:    []string{"/tmp:rw,nosuid,nodev,size=64m"},
			CapDrop:  []string{"ALL"},
			SecurityOpt: []string{
				"no-new-privileges:true",
			},
			MemLimit:    memLimit,
			CPUs:        cpus,
			PidsLimit:   pids,
			Labels:      labels,
			Environment: target.Environment,
		}

		if target.Image != "" {
			svc.Image = target.Image
		} else if target.Build.Dockerfile != "" {
			ctxPath := filepath.Join(labDir, target.Build.Context)
			if target.Build.Context == "." || target.Build.Context == "" {
				ctxPath = labDir
			}
			svc.Build = &ComposeBuild{
				Context:    ctxPath,
				Dockerfile: target.Build.Dockerfile,
			}
		}

		// Host port publication handling
		if m.HostAccess.Publish && cfg.Security.AllowHostPortPublish {
			bindAddr := m.HostAccess.BindAddress
			if bindAddr == "" {
				bindAddr = "127.0.0.1"
			}
			for extPort, intPort := range m.HostAccess.RequestedPorts {
				svc.Ports = append(svc.Ports, fmt.Sprintf("%s:%s:%d", bindAddr, extPort, intPort))
			}
		}

		services[target.Name] = svc
	}

	// Runner container service
	wsMount := m.Runner.WorkspaceMount
	if wsMount == "" {
		wsMount = m.Workspace
	}
	if wsMount == "" {
		wsMount = "."
	}
	wsHostPath := filepath.Join(labDir, wsMount)
	if wsMount == "." {
		wsHostPath = labDir
	}

	runnerMem := m.Limits.RunnerMemory
	if runnerMem == "" {
		runnerMem = "1g"
	}
	runnerCPUs := m.Limits.RunnerCPUs
	if runnerCPUs == 0 {
		runnerCPUs = 1.0
	}
	runnerPIDs := m.Limits.RunnerPIDs
	if runnerPIDs == 0 {
		runnerPIDs = 256
	}

	scratchVolName := fmt.Sprintf("scratch-%s", sessID)

	// Invariants: Read-only workspace bind mount, dedicated scratch volume, cap_drop ALL, no-new-privileges, internal network
	services["runner"] = ComposeService{
		Image:      cfg.Runner.Image,
		DependsOn:  targetNames,
		WorkingDir: "/workspace",
		Command:    []string{"sleep", "infinity"},
		Volumes: []ComposeVolumeRef{
			{
				Type:     "bind",
				Source:   wsHostPath,
				Target:   "/workspace",
				ReadOnly: true, // Invariant 4: Workspace is read-only
			},
			{
				Type:   "volume",
				Source: scratchVolName,
				Target: "/scratch", // Invariant 5: Scratch is writable agent directory
			},
		},
		Networks: []string{"lab"},
		ReadOnly: true,
		Tmpfs:    []string{"/tmp:rw,nosuid,nodev,size=128m"},
		CapDrop:  []string{"ALL"}, // Invariant 16: Dropped capabilities
		SecurityOpt: []string{
			"no-new-privileges:true", // Invariant 17: no-new-privileges
		},
		MemLimit:  runnerMem,
		CPUs:      runnerCPUs,
		PidsLimit: runnerPIDs,
		Labels:    labels,
	}

	// Networks (Invariant 6: Target and runner use internal network)
	networks := map[string]ComposeNetwork{
		"lab": {
			Internal: !cfg.Security.AllowInternetEgress,
			Labels:   labels,
		},
	}

	// Volumes
	volumes := map[string]ComposeVolume{
		scratchVolName: {
			Labels: labels,
		},
	}

	composeConfig := ComposeConfig{
		Version:  "3.8",
		Services: services,
		Networks: networks,
		Volumes:  volumes,
	}

	data, err := yaml.Marshal(composeConfig)
	if err != nil {
		return "", fmt.Errorf("failed to marshal docker-compose file: %w", err)
	}

	return string(data), nil
}
