package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/pathsafe"
	"gopkg.in/yaml.v3"
)

var (
	ErrInvalidConfig    = errors.New("invalid configuration")
	ErrVersion1Obsolete = errors.New("configuration version 1 is obsolete; please update configuration to version 2 (remove lab_root and add network settings)")
)

type Config struct {
	Version   int            `yaml:"version" json:"version"`
	StateDir  string         `yaml:"state_dir" json:"state_dir"`
	AuditLog  string         `yaml:"audit_log" json:"audit_log"`
	ExportDir string         `yaml:"export_dir" json:"export_dir"`
	Runner    RunnerConfig   `yaml:"runner" json:"runner"`
	Network   NetworkConfig  `yaml:"network" json:"network"`
	Limits    LimitsConfig   `yaml:"limits" json:"limits"`
	Security  SecurityConfig `yaml:"security" json:"security"`
	Logging   LoggingConfig  `yaml:"logging" json:"logging"`
}

type RunnerConfig struct {
	Image      string `yaml:"image" json:"image"`
	Dockerfile string `yaml:"dockerfile" json:"dockerfile"`
	PullPolicy string `yaml:"pull_policy" json:"pull_policy"`
}

type NetworkConfig struct {
	OutboundEnabled    bool   `yaml:"outbound_enabled" json:"outbound_enabled"`
	HostGatewayEnabled bool   `yaml:"host_gateway_enabled" json:"host_gateway_enabled"`
	HostGatewayName    string `yaml:"host_gateway_name" json:"host_gateway_name"`
}

type LimitsConfig struct {
	DefaultTimeoutSeconds         int   `yaml:"default_timeout_seconds" json:"default_timeout_seconds"`
	MaximumTimeoutSeconds         int   `yaml:"maximum_timeout_seconds" json:"maximum_timeout_seconds"`
	ShutdownGraceSeconds          int   `yaml:"shutdown_grace_seconds" json:"shutdown_grace_seconds"`
	MaximumOutputBytes            int64 `yaml:"maximum_output_bytes" json:"maximum_output_bytes"`
	MaximumWriteBytes             int64 `yaml:"maximum_write_bytes" json:"maximum_write_bytes"`
	MaximumReadBytes              int64 `yaml:"maximum_read_bytes" json:"maximum_read_bytes"`
	MaximumExportBytes            int64 `yaml:"maximum_export_bytes" json:"maximum_export_bytes"`
	DefaultSessionTTLMinutes      int   `yaml:"default_session_ttl_minutes" json:"default_session_ttl_minutes"`
	MaximumSessionTTLMinutes      int   `yaml:"maximum_session_ttl_minutes" json:"maximum_session_ttl_minutes"`
	MaximumSessions               int   `yaml:"maximum_sessions" json:"maximum_sessions"`
	MaximumParallelExecPerSession int   `yaml:"maximum_parallel_exec_per_session" json:"maximum_parallel_exec_per_session"`
	MaximumParallelGlobalExec     int   `yaml:"maximum_parallel_global_exec" json:"maximum_parallel_global_exec"`
}

type SecurityConfig struct {
	AllowExport                 bool   `yaml:"allow_export" json:"allow_export"`
	PreserveScratchOnStop       bool   `yaml:"preserve_scratch_on_stop" json:"preserve_scratch_on_stop"`
	RemoveSessionOnStartFailure bool   `yaml:"remove_session_on_start_failure" json:"remove_session_on_start_failure"`
	CommandPolicy               string `yaml:"command_policy" json:"command_policy"`
	AllowHostFilesystemMounts   bool   `yaml:"allow_host_filesystem_mounts" json:"allow_host_filesystem_mounts"`
	AllowDockerSocket           bool   `yaml:"allow_docker_socket" json:"allow_docker_socket"`
	AllowPrivileged             bool   `yaml:"allow_privileged" json:"allow_privileged"`
	AllowHostNetwork            bool   `yaml:"allow_host_network" json:"allow_host_network"`
}

type LoggingConfig struct {
	Level                     string `yaml:"level" json:"level"`
	IncludeCommands           bool   `yaml:"include_commands" json:"include_commands"`
	IncludeCommandOutput      bool   `yaml:"include_command_output" json:"include_command_output"`
	RedactEnvironmentValues   bool   `yaml:"redact_environment_values" json:"redact_environment_values"`
	RedactKnownSecretPatterns bool   `yaml:"redact_known_secret_patterns" json:"redact_known_secret_patterns"`
}

// DefaultConfig returns secure default version 2 configuration settings.
func DefaultConfig() *Config {
	home, _ := os.UserHomeDir()
	if home == "" {
		home = "."
	}
	defaultState := filepath.Join(home, ".ai-security-lab-runner")

	return &Config{
		Version:   2,
		StateDir:  defaultState,
		AuditLog:  filepath.Join(defaultState, "audit.jsonl"),
		ExportDir: filepath.Join(defaultState, "exports"),
		Runner: RunnerConfig{
			Image:      "ai-security-agent-runner:latest",
			Dockerfile: "runner/Dockerfile",
			PullPolicy: "never",
		},
		Network: NetworkConfig{
			OutboundEnabled:    true,
			HostGatewayEnabled: true,
			HostGatewayName:    "host.docker.internal",
		},
		Limits: LimitsConfig{
			DefaultTimeoutSeconds:         30,
			MaximumTimeoutSeconds:         120,
			ShutdownGraceSeconds:          10,
			MaximumOutputBytes:            1048576, // 1MB
			MaximumWriteBytes:             1048576, // 1MB
			MaximumReadBytes:              2097152, // 2MB
			MaximumExportBytes:            5242880, // 5MB
			DefaultSessionTTLMinutes:      60,
			MaximumSessionTTLMinutes:      240,
			MaximumSessions:               4,
			MaximumParallelExecPerSession: 1,
			MaximumParallelGlobalExec:     4,
		},
		Security: SecurityConfig{
			AllowExport:                 false,
			PreserveScratchOnStop:       false,
			RemoveSessionOnStartFailure: true,
			CommandPolicy:               "container-only",
			AllowHostFilesystemMounts:   false,
			AllowDockerSocket:           false,
			AllowPrivileged:             false,
			AllowHostNetwork:            false,
		},
		Logging: LoggingConfig{
			Level:                     "info",
			IncludeCommands:           true,
			IncludeCommandOutput:      false,
			RedactEnvironmentValues:   true,
			RedactKnownSecretPatterns: true,
		},
	}
}

// LoadConfig loads configuration from a YAML file if path is provided, applies environment overrides, and validates version 2.
func LoadConfig(configPath string) (*Config, error) {
	cfg := DefaultConfig()

	if configPath != "" {
		cleanPath, err := pathsafe.CleanHostPath(configPath)
		if err != nil {
			return nil, fmt.Errorf("invalid config file path: %w", err)
		}
		data, err := os.ReadFile(cleanPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file '%s': %w", cleanPath, err)
		}

		// Pre-check version in raw map to detect version 1 configs
		var rawMap map[string]interface{}
		if err := yaml.Unmarshal(data, &rawMap); err == nil {
			if v, ok := rawMap["version"].(int); ok && v == 1 {
				return nil, ErrVersion1Obsolete
			}
			if _, ok := rawMap["lab_root"]; ok {
				return nil, ErrVersion1Obsolete
			}
		}

		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("failed to parse config YAML: %w", err)
		}
	}

	cfg.applyEnvOverrides()

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return cfg, nil
}

func (c *Config) applyEnvOverrides() {
	if val := os.Getenv("LAB_RUNNER_STATE_DIR"); val != "" {
		c.StateDir = val
	}
	if val := os.Getenv("LAB_RUNNER_AUDIT_LOG"); val != "" {
		c.AuditLog = val
	}
	if val := os.Getenv("LAB_RUNNER_EXPORT_DIR"); val != "" {
		c.ExportDir = val
	}
	if val := os.Getenv("LAB_RUNNER_RUNNER_IMAGE"); val != "" {
		c.Runner.Image = val
	}
	if val := os.Getenv("LAB_RUNNER_ALLOW_EXPORT"); val != "" {
		c.Security.AllowExport = strings.ToLower(val) == "true" || val == "1"
	}
	if val := os.Getenv("LAB_RUNNER_OUTBOUND_ENABLED"); val != "" {
		c.Network.OutboundEnabled = strings.ToLower(val) == "true" || val == "1"
	}
	if val := os.Getenv("LAB_RUNNER_MAX_SESSIONS"); val != "" {
		if n, err := strconv.Atoi(val); err == nil {
			c.Limits.MaximumSessions = n
		}
	}
}

// Validate checks all version 2 configuration rules and canonicalizes paths.
func (c *Config) Validate() error {
	if c.Version == 1 {
		return ErrVersion1Obsolete
	}
	if c.Version != 2 {
		return fmt.Errorf("%w: unsupported configuration version %d", ErrInvalidConfig, c.Version)
	}

	var err error
	if c.StateDir, err = pathsafe.CleanHostPath(c.StateDir); err != nil {
		return fmt.Errorf("state_dir path invalid: %w", err)
	}
	if c.AuditLog, err = pathsafe.CleanHostPath(c.AuditLog); err != nil {
		return fmt.Errorf("audit_log path invalid: %w", err)
	}
	if c.ExportDir, err = pathsafe.CleanHostPath(c.ExportDir); err != nil {
		return fmt.Errorf("export_dir path invalid: %w", err)
	}

	if c.Security.CommandPolicy != "container-only" {
		return fmt.Errorf("%w: command_policy must be 'container-only'", ErrInvalidConfig)
	}
	if c.Security.AllowHostFilesystemMounts {
		return fmt.Errorf("%w: allow_host_filesystem_mounts must be false", ErrInvalidConfig)
	}
	if c.Security.AllowDockerSocket {
		return fmt.Errorf("%w: allow_docker_socket must be false", ErrInvalidConfig)
	}
	if c.Security.AllowPrivileged {
		return fmt.Errorf("%w: allow_privileged must be false", ErrInvalidConfig)
	}
	if c.Security.AllowHostNetwork {
		return fmt.Errorf("%w: allow_host_network must be false", ErrInvalidConfig)
	}

	if c.Limits.DefaultTimeoutSeconds <= 0 || c.Limits.MaximumTimeoutSeconds < c.Limits.DefaultTimeoutSeconds {
		return fmt.Errorf("%w: invalid timeout parameters", ErrInvalidConfig)
	}
	if c.Limits.MaximumSessions <= 0 {
		return fmt.Errorf("%w: maximum_sessions must be greater than 0", ErrInvalidConfig)
	}

	return nil
}
