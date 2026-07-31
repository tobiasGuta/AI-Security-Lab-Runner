package manifest

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ai-security-lab-runner/lab-runner/internal/pathsafe"
	"gopkg.in/yaml.v3"
)

var (
	ErrInvalidManifest = errors.New("invalid lab manifest")
	ErrUnsafeManifest  = errors.New("unsafe lab manifest setting")

	validNamePattern   = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	validEnvKeyPattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
)

type LabManifest struct {
	Version     int            `yaml:"version" json:"version"`
	Name        string         `yaml:"name" json:"name"`
	Description string         `yaml:"description" json:"description"`
	Workspace   string         `yaml:"workspace" json:"workspace"`
	Targets     []TargetSpec   `yaml:"targets" json:"targets"`
	HostAccess  HostAccessSpec `yaml:"host_access" json:"host_access"`
	Limits      ResourceLimits `yaml:"limits" json:"limits"`
	Runner      RunnerLabSpec  `yaml:"runner" json:"runner"`

	// Dir is set during loading to track absolute lab directory
	Dir string `yaml:"-" json:"-"`
}

type TargetSpec struct {
	Name         string            `yaml:"name" json:"name"`
	Build        BuildSpec         `yaml:"build" json:"build"`
	Image        string            `yaml:"image,omitempty" json:"image,omitempty"`
	InternalPort int               `yaml:"internal_port" json:"internal_port"`
	HealthCheck  HealthCheckSpec   `yaml:"healthcheck" json:"healthcheck"`
	Environment  map[string]string `yaml:"environment" json:"environment"`
	Limits       ResourceLimits    `yaml:"limits,omitempty" json:"limits,omitempty"`
}

type BuildSpec struct {
	Context    string `yaml:"context" json:"context"`
	Dockerfile string `yaml:"dockerfile" json:"dockerfile"`
}

type HealthCheckSpec struct {
	URL             string `yaml:"url" json:"url"`
	TimeoutSeconds  int    `yaml:"timeout_seconds" json:"timeout_seconds"`
	IntervalSeconds int    `yaml:"interval_seconds" json:"interval_seconds"`
}

type HostAccessSpec struct {
	Publish        bool           `yaml:"publish" json:"publish"`
	BindAddress    string         `yaml:"bind_address" json:"bind_address"`
	RequestedPorts map[string]int `yaml:"requested_ports" json:"requested_ports"`
}

type ResourceLimits struct {
	TargetMemory string  `yaml:"target_memory" json:"target_memory"`
	TargetCPUs   float64 `yaml:"target_cpus" json:"target_cpus"`
	TargetPIDs   int     `yaml:"target_pids" json:"target_pids"`
	RunnerMemory string  `yaml:"runner_memory" json:"runner_memory"`
	RunnerCPUs   float64 `yaml:"runner_cpus" json:"runner_cpus"`
	RunnerPIDs   int     `yaml:"runner_pids" json:"runner_pids"`
}

type RunnerLabSpec struct {
	WorkspaceMount    string `yaml:"workspace_mount" json:"workspace_mount"`
	ScratchPersistent bool   `yaml:"scratch_persistent" json:"scratch_persistent"`
}

// LoadManifest reads, parses, and validates labrunner.yaml from a lab directory.
func LoadManifest(labDir string) (*LabManifest, error) {
	cleanDir, err := pathsafe.CleanHostPath(labDir)
	if err != nil {
		return nil, fmt.Errorf("invalid lab directory: %w", err)
	}

	manifestPath := filepath.Join(cleanDir, "labrunner.yaml")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read labrunner.yaml in '%s': %w", cleanDir, err)
	}

	var m LabManifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("%w: failed to parse YAML: %v", ErrInvalidManifest, err)
	}
	m.Dir = cleanDir

	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("manifest validation failed: %w", err)
	}

	return &m, nil
}

// Validate checks all security rules for labrunner.yaml.
func (m *LabManifest) Validate() error {
	if m.Version != 1 {
		return fmt.Errorf("%w: unsupported version %d", ErrInvalidManifest, m.Version)
	}

	if !validNamePattern.MatchString(m.Name) {
		return fmt.Errorf("%w: invalid lab name '%s'", ErrInvalidManifest, m.Name)
	}

	// Validate workspace path
	if err := validateRelativeLabPath(m.Workspace, m.Dir); err != nil {
		return fmt.Errorf("workspace path invalid: %w", err)
	}

	if len(m.Targets) == 0 {
		return fmt.Errorf("%w: at least one target service must be defined", ErrInvalidManifest)
	}

	targetNames := make(map[string]bool)
	for i, target := range m.Targets {
		if !validNamePattern.MatchString(target.Name) {
			return fmt.Errorf("%w: target[%d] invalid name '%s'", ErrInvalidManifest, i, target.Name)
		}
		if targetNames[target.Name] {
			return fmt.Errorf("%w: duplicate target name '%s'", ErrInvalidManifest, target.Name)
		}
		targetNames[target.Name] = true

		if target.Name == "runner" {
			return fmt.Errorf("%w: target name cannot be 'runner' (reserved for system)", ErrInvalidManifest)
		}

		if target.Build.Context != "" {
			if err := validateRelativeLabPath(target.Build.Context, m.Dir); err != nil {
				return fmt.Errorf("target '%s' build context invalid: %w", target.Name, err)
			}
		}
		if target.Build.Dockerfile != "" {
			if err := validateRelativeLabPath(target.Build.Dockerfile, m.Dir); err != nil {
				return fmt.Errorf("target '%s' dockerfile invalid: %w", target.Name, err)
			}
		}

		// Environment variables checks
		if len(target.Environment) > 50 {
			return fmt.Errorf("%w: target '%s' exceeds 50 environment variables limit", ErrUnsafeManifest, target.Name)
		}
		for k, v := range target.Environment {
			if !validEnvKeyPattern.MatchString(k) {
				return fmt.Errorf("%w: target '%s' invalid env key '%s'", ErrInvalidManifest, target.Name, k)
			}
			if len(v) > 4096 {
				return fmt.Errorf("%w: target '%s' env value '%s' exceeds 4096 bytes", ErrUnsafeManifest, target.Name, k)
			}
			if strings.Contains(v, "\x00") {
				return fmt.Errorf("%w: target '%s' env value contains null bytes", ErrUnsafeManifest, target.Name)
			}
		}
	}

	// Host access checks
	if m.HostAccess.BindAddress != "" && m.HostAccess.BindAddress != "127.0.0.1" && m.HostAccess.BindAddress != "::1" {
		return fmt.Errorf("%w: bind_address must be '127.0.0.1' or '::1'", ErrUnsafeManifest)
	}

	// Runner spec validation
	if m.Runner.WorkspaceMount == "" {
		m.Runner.WorkspaceMount = "."
	}
	if err := validateRelativeLabPath(m.Runner.WorkspaceMount, m.Dir); err != nil {
		return fmt.Errorf("runner.workspace_mount invalid: %w", err)
	}

	return nil
}

func validateRelativeLabPath(relPath, labDir string) error {
	if relPath == "" {
		return nil
	}
	if filepath.IsAbs(relPath) || strings.HasPrefix(relPath, "/") || strings.HasPrefix(relPath, "\\") {
		return fmt.Errorf("%w: absolute paths are not allowed: '%s'", ErrUnsafeManifest, relPath)
	}
	if strings.Contains(relPath, "..") {
		return fmt.Errorf("%w: parent path traversal '..' is not allowed: '%s'", ErrUnsafeManifest, relPath)
	}

	joined := filepath.Join(labDir, relPath)
	_, err := pathsafe.ValidateHostPathUnderRoot(joined, labDir)
	if err != nil {
		return fmt.Errorf("%w: path '%s' escapes lab root '%s'", ErrUnsafeManifest, relPath, labDir)
	}

	return nil
}
