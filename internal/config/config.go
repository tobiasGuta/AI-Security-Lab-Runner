package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/ai-security-lab-runner/lab-runner/internal/pathsafe"
	"gopkg.in/yaml.v3"
)

var (
	ErrInvalidConfig = errors.New("invalid configuration")
	ErrUnsafePath    = errors.New("unsafe path in configuration")
)

type Config struct {
	Version   int            `yaml:"version" json:"version"`
	LabRoot   string         `yaml:"lab_root" json:"lab_root"`
	StateDir  string         `yaml:"state_dir" json:"state_dir"`
	AuditLog  string         `yaml:"audit_log" json:"audit_log"`
	ExportDir string         `yaml:"export_dir" json:"export_dir"`
	Runner    RunnerConfig   `yaml:"runner" json:"runner"`
	Limits    LimitsConfig   `yaml:"limits" json:"limits"`
	Security  SecurityConfig `yaml:"security" json:"security"`
	Logging   LoggingConfig  `yaml:"logging" json:"logging"`
}

type RunnerConfig struct {
	Image      string `yaml:"image" json:"image"`
	Dockerfile string `yaml:"dockerfile" json:"dockerfile"`
	PullPolicy string `yaml:"pull_policy" json:"pull_policy"`
}

type LimitsConfig struct {
	DefaultTimeoutSeconds         int   `yaml:"default_timeout_seconds" json:"default_timeout_seconds"`
	MaximumTimeoutSeconds         int   `yaml:"maximum_timeout_seconds" json:"maximum_timeout_seconds"`
	ShutdownGraceSeconds          int   `yaml:"shutdown_grace_seconds" json:"shutdown_grace_seconds"`
	MaximumOutputBytes            int64 `yaml:"maximum_output_bytes" json:"maximum_output_bytes"`
	MaximumWriteBytes             int64 `yaml:"maximum_write_bytes" json:"maximum_write_bytes"`
	MaximumReadBytes              int64 `yaml:"maximum_read_bytes" json:"maximum_read_bytes"`
	MaximumExportBytes            int64 `yaml:"maximum_export_bytes" json:"maximum_export_bytes"`
	SessionTTLMinutes             int   `yaml:"session_ttl_minutes" json:"session_ttl_minutes"`
	MaximumSessions               int   `yaml:"maximum_sessions" json:"maximum_sessions"`
	MaximumParallelExecPerSession int   `yaml:"maximum_parallel_exec_per_session" json:"maximum_parallel_exec_per_session"`
	MaximumParallelGlobalExec     int   `yaml:"maximum_parallel_global_exec" json:"maximum_parallel_global_exec"`
}

type SecurityConfig struct {
	AllowExport                 bool   `yaml:"allow_export" json:"allow_export"`
	AllowHostPortPublish        bool   `yaml:"allow_host_port_publish" json:"allow_host_port_publish"`
	PreserveScratchOnStop       bool   `yaml:"preserve_scratch_on_stop" json:"preserve_scratch_on_stop"`
	RemoveSessionOnStartFailure bool   `yaml:"remove_session_on_start_failure" json:"remove_session_on_start_failure"`
	RequireInternalNetwork      bool   `yaml:"require_internal_network" json:"require_internal_network"`
	AllowInternetEgress         bool   `yaml:"allow_internet_egress" json:"allow_internet_egress"`
	CommandPolicy               string `yaml:"command_policy" json:"command_policy"`
}

type LoggingConfig struct {
	Level                     string `yaml:"level" json:"level"`
	IncludeCommands           bool   `yaml:"include_commands" json:"include_commands"`
	IncludeCommandOutput      bool   `yaml:"include_command_output" json:"include_command_output"`
	RedactEnvironmentValues   bool   `yaml:"redact_environment_values" json:"redact_environment_values"`
	RedactKnownSecretPatterns bool   `yaml:"redact_known_secret_patterns" json:"redact_known_secret_patterns"`
}

// DefaultConfig returns secure default configuration settings.
func DefaultConfig() *Config {
	home, _ := os.UserHomeDir()
	if home == "" {
		home = "."
	}
	defaultState := filepath.Join(home, ".ai-security-lab-runner")

	return &Config{
		Version:   1,
		LabRoot:   filepath.Join(home, "ai-security-labs"),
		StateDir:  defaultState,
		AuditLog:  filepath.Join(defaultState, "audit.jsonl"),
		ExportDir: filepath.Join(defaultState, "exports"),
		Runner: RunnerConfig{
			Image:      "ai-security-agent-runner:latest",
			Dockerfile: "",
			PullPolicy: "never",
		},
		Limits: LimitsConfig{
			DefaultTimeoutSeconds:         30,
			MaximumTimeoutSeconds:         120,
			ShutdownGraceSeconds:          10,
			MaximumOutputBytes:            1048576, // 1MB
			MaximumWriteBytes:             1048576, // 1MB
			MaximumReadBytes:              2097152, // 2MB
			MaximumExportBytes:            5242880, // 5MB
			SessionTTLMinutes:             120,
			MaximumSessions:               4,
			MaximumParallelExecPerSession: 1,
			MaximumParallelGlobalExec:     4,
		},
		Security: SecurityConfig{
			AllowExport:                 false,
			AllowHostPortPublish:        false,
			PreserveScratchOnStop:       false,
			RemoveSessionOnStartFailure: true,
			RequireInternalNetwork:      true,
			AllowInternetEgress:         false,
			CommandPolicy:               "container-only",
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

// LoadConfig loads configuration from a YAML file if path is provided, applies environment variables, and validates.
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
	if val := os.Getenv("LAB_RUNNER_LAB_ROOT"); val != "" {
		c.LabRoot = val
	}
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
	if val := os.Getenv("LAB_RUNNER_ALLOW_INTERNET"); val != "" {
		c.Security.AllowInternetEgress = strings.ToLower(val) == "true" || val == "1"
	}
	if val := os.Getenv("LAB_RUNNER_MAX_SESSIONS"); val != "" {
		if n, err := strconv.Atoi(val); err == nil {
			c.Limits.MaximumSessions = n
		}
	}
}

// Validate checks all configuration security rules and canonicalizes paths.
func (c *Config) Validate() error {
	if c.Version != 1 {
		return fmt.Errorf("%w: unsupported configuration version %d", ErrInvalidConfig, c.Version)
	}

	// Canonicalize paths
	var err error
	if c.LabRoot, err = pathsafe.CleanHostPath(c.LabRoot); err != nil {
		return fmt.Errorf("lab_root path invalid: %w", err)
	}
	if c.StateDir, err = pathsafe.CleanHostPath(c.StateDir); err != nil {
		return fmt.Errorf("state_dir path invalid: %w", err)
	}
	if c.AuditLog, err = pathsafe.CleanHostPath(c.AuditLog); err != nil {
		return fmt.Errorf("audit_log path invalid: %w", err)
	}
	if c.ExportDir, err = pathsafe.CleanHostPath(c.ExportDir); err != nil {
		return fmt.Errorf("export_dir path invalid: %w", err)
	}

	// Reject root / entire drive / home directory as lab_root
	if err := checkNotBroadRoot(c.LabRoot); err != nil {
		return fmt.Errorf("lab_root rejected: %w", err)
	}

	// Security invariants check
	if c.Security.CommandPolicy != "container-only" {
		return fmt.Errorf("%w: command_policy must be 'container-only'", ErrInvalidConfig)
	}

	// Limits validation
	if c.Limits.DefaultTimeoutSeconds <= 0 || c.Limits.MaximumTimeoutSeconds < c.Limits.DefaultTimeoutSeconds {
		return fmt.Errorf("%w: invalid timeout parameters", ErrInvalidConfig)
	}
	if c.Limits.MaximumSessions <= 0 {
		return fmt.Errorf("%w: maximum_sessions must be greater than 0", ErrInvalidConfig)
	}

	return nil
}

func checkNotBroadRoot(p string) error {
	abs, err := filepath.Abs(p)
	if err != nil {
		return err
	}
	clean := filepath.Clean(abs)

	// Check filesystem root (e.g. "/" or "C:\")
	root := filepath.VolumeName(clean) + string(filepath.Separator)
	if clean == root || clean == "/" || clean == "\\" {
		return fmt.Errorf("%w: cannot use filesystem root '%s' as lab_root", ErrUnsafePath, p)
	}

	// Check user home directory
	home, _ := os.UserHomeDir()
	if home != "" && filepath.Clean(home) == clean {
		return fmt.Errorf("%w: cannot use user home directory '%s' directly as lab_root", ErrUnsafePath, p)
	}

	// Check system directories on Windows/Linux
	if runtime.GOOS == "windows" {
		windir := os.Getenv("SystemRoot")
		if windir != "" && filepath.Clean(windir) == clean {
			return fmt.Errorf("%w: cannot use SystemRoot as lab_root", ErrUnsafePath)
		}
	}

	return nil
}
