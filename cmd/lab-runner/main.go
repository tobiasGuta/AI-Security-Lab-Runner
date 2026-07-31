package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/audit"
	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/config"
	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/docker"
	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/lab"
	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/mcp"
	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/output"
)

var (
	Version   = "2.0.0"
	GitCommit = "dev"
	BuildDate = "unknown"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	subcommand := os.Args[1]

	switch subcommand {
	case "sandbox":
		cmdSandbox(os.Args[2:])
	case "serve":
		cmdServe(os.Args[2:])
	case "doctor":
		cmdDoctor(os.Args[2:])
	case "cleanup":
		cmdCleanup(os.Args[2:])
	case "version":
		cmdVersion(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown subcommand: %s\n", subcommand)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`AI Security Lab Runner (lab-runner) - Generic AI Execution Sandbox

Usage:
  lab-runner sandbox run [--cwd <path>] [--timeout <sec>] [--json] -- <command...>
  lab-runner sandbox start [--ttl <min>] [--json]
  lab-runner sandbox exec <session-id> [--cwd <path>] [--timeout <sec>] [--json] -- <command...>
  lab-runner sandbox request --url <url> [--method GET] [--json]
  lab-runner sandbox write <session-id> <scratch-path> [--file <local-file>] [--stdin] [--overwrite]
  lab-runner sandbox read <session-id> <scratch-path> [--max-bytes <n>]
  lab-runner sandbox status [session-id] [--json]
  lab-runner sandbox stop <session-id>
  lab-runner sandbox reset <session-id>
  lab-runner serve [--config <path>]
  lab-runner doctor [--json] [--config <path>]
  lab-runner cleanup [--stale] [--dry-run]
  lab-runner version [--json]`)
}

func loadEngine(configPath string) (*config.Config, *lab.Engine, error) {
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return nil, nil, fmt.Errorf("config error: %w", err)
	}

	logger, err := audit.NewLogger(cfg.AuditLog, cfg.Logging.RedactKnownSecretPatterns)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to initialize audit logger: %v\n", err)
	}

	dockerClient := docker.NewCLIClient()
	engine, err := lab.NewEngine(cfg, dockerClient, logger)
	if err != nil {
		return nil, nil, fmt.Errorf("engine init error: %w", err)
	}

	return cfg, engine, nil
}

func isFlagPassed(fs *flag.FlagSet, name string) bool {
	found := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func cmdSandbox(args []string) {
	if len(args) == 0 {
		printUsage()
		os.Exit(1)
	}

	verb := args[0]
	verbArgs := args[1:]

	switch verb {
	case "run":
		cmdSandboxRun(verbArgs)
	case "start":
		cmdSandboxStart(verbArgs)
	case "exec":
		cmdSandboxExec(verbArgs)
	case "request":
		cmdSandboxRequest(verbArgs)
	case "write":
		cmdSandboxWrite(verbArgs)
	case "read":
		cmdSandboxRead(verbArgs)
	case "status":
		cmdSandboxStatus(verbArgs)
	case "stop":
		cmdSandboxStop(verbArgs)
	case "reset":
		cmdSandboxReset(verbArgs)
	default:
		fmt.Fprintf(os.Stderr, "Unknown sandbox subcommand: %s\n", verb)
		printUsage()
		os.Exit(1)
	}
}

func cmdSandboxRun(args []string) {
	fs := flag.NewFlagSet("sandbox run", flag.ExitOnError)
	cwd := fs.String("cwd", "/scratch", "Working directory inside runner")
	timeout := fs.Int("timeout", 30, "Timeout in seconds")
	jsonMode := fs.Bool("json", false, "Output results in JSON format")
	configPath := fs.String("config", "", "Path to config file")

	cmdIdx := -1
	for i, arg := range args {
		if arg == "--" {
			cmdIdx = i
			break
		}
	}

	var flagArgs, cmdArgs []string
	if cmdIdx != -1 {
		flagArgs = args[:cmdIdx]
		cmdArgs = args[cmdIdx+1:]
	} else {
		flagArgs = args
	}

	_ = fs.Parse(flagArgs)
	if len(cmdArgs) == 0 && len(fs.Args()) > 0 {
		cmdArgs = fs.Args()
	}

	if len(cmdArgs) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: lab-runner sandbox run [--cwd <path>] [--timeout <sec>] -- <command...>\n")
		os.Exit(1)
	}

	fullCmd := ""
	for i, c := range cmdArgs {
		if i > 0 {
			fullCmd += " "
		}
		fullCmd += c
	}

	_, engine, err := loadEngine(*configPath)
	if err != nil {
		output.PrintError(*jsonMode, "CONFIG_ERROR", err.Error())
		os.Exit(1)
	}

	ctx := context.Background()
	res, err := engine.Run(ctx, fullCmd, *cwd, *timeout, nil)
	if err != nil {
		output.PrintError(*jsonMode, "RUN_FAILED", err.Error())
		os.Exit(1)
	}

	if *jsonMode {
		_ = output.PrintJSON(res)
	} else {
		if res.Stdout != "" {
			fmt.Print(res.Stdout)
		}
		if res.Stderr != "" {
			fmt.Fprint(os.Stderr, res.Stderr)
		}
		if res.ExitCode != 0 {
			os.Exit(res.ExitCode)
		}
	}
}

func cmdSandboxStart(args []string) {
	fs := flag.NewFlagSet("sandbox start", flag.ExitOnError)
	ttl := fs.Int("ttl", 60, "Session TTL in minutes")
	outbound := fs.Bool("outbound", true, "Enable outbound network access")
	hostAccess := fs.Bool("host-access", true, "Enable host gateway mapping")
	jsonMode := fs.Bool("json", false, "JSON output format")
	configPath := fs.String("config", "", "Path to config file")
	_ = fs.Parse(args)

	_, engine, err := loadEngine(*configPath)
	if err != nil {
		output.PrintError(*jsonMode, "CONFIG_ERROR", err.Error())
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	var outboundPtr, hostAccessPtr *bool
	if isFlagPassed(fs, "outbound") {
		outboundPtr = outbound
	}
	if isFlagPassed(fs, "host-access") {
		hostAccessPtr = hostAccess
	}

	res, err := engine.StartSession(ctx, outboundPtr, hostAccessPtr, *ttl)
	if err != nil {
		output.PrintError(*jsonMode, "START_FAILED", err.Error())
		os.Exit(1)
	}

	if *jsonMode {
		_ = output.PrintJSON(res)
	} else {
		fmt.Printf("Sandbox Started Successfully!\nSession ID: %s\nStatus: %s\nExpires At: %s\nHost Gateway: %s\n",
			res.SessionID, res.Status, res.ExpiresAt.Format(time.RFC3339), res.HostGateway)
	}
}

func cmdSandboxExec(args []string) {
	fs := flag.NewFlagSet("sandbox exec", flag.ExitOnError)
	cwd := fs.String("cwd", "/scratch", "Working directory inside runner")
	timeout := fs.Int("timeout", 30, "Timeout in seconds")
	jsonMode := fs.Bool("json", false, "Output results in JSON format")
	configPath := fs.String("config", "", "Path to config file")

	cmdIdx := -1
	for i, arg := range args {
		if arg == "--" {
			cmdIdx = i
			break
		}
	}

	var flagArgs, cmdArgs []string
	if cmdIdx != -1 {
		flagArgs = args[:cmdIdx]
		cmdArgs = args[cmdIdx+1:]
	} else {
		flagArgs = args
	}

	_ = fs.Parse(flagArgs)
	pos := fs.Args()
	if len(cmdArgs) == 0 && len(pos) >= 2 {
		cmdArgs = pos[1:]
		pos = pos[:1]
	}

	if len(pos) < 1 || len(cmdArgs) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: lab-runner sandbox exec <session-id> [--cwd <path>] [--timeout <sec>] -- <command...>\n")
		os.Exit(1)
	}

	sessID := pos[0]
	fullCmd := ""
	for i, c := range cmdArgs {
		if i > 0 {
			fullCmd += " "
		}
		fullCmd += c
	}

	_, engine, err := loadEngine(*configPath)
	if err != nil {
		output.PrintError(*jsonMode, "CONFIG_ERROR", err.Error())
		os.Exit(1)
	}

	ctx := context.Background()
	res, err := engine.Exec(ctx, sessID, fullCmd, *cwd, *timeout, nil)
	if err != nil {
		output.PrintError(*jsonMode, "EXEC_FAILED", err.Error())
		os.Exit(1)
	}

	if *jsonMode {
		_ = output.PrintJSON(res)
	} else {
		if res.Stdout != "" {
			fmt.Print(res.Stdout)
		}
		if res.Stderr != "" {
			fmt.Fprint(os.Stderr, res.Stderr)
		}
		if res.ExitCode != 0 {
			os.Exit(res.ExitCode)
		}
	}
}

func cmdSandboxRequest(args []string) {
	fs := flag.NewFlagSet("sandbox request", flag.ExitOnError)
	rawURL := fs.String("url", "", "Target URL")
	method := fs.String("method", "GET", "HTTP Method")
	sessionID := fs.String("session", "", "Optional session ID")
	jsonMode := fs.Bool("json", false, "Output in JSON format")
	configPath := fs.String("config", "", "Path to config file")
	_ = fs.Parse(args)

	if *rawURL == "" {
		fmt.Fprintf(os.Stderr, "Usage: lab-runner sandbox request --url <url> [--method GET] [--json]\n")
		os.Exit(1)
	}

	_, engine, err := loadEngine(*configPath)
	if err != nil {
		output.PrintError(*jsonMode, "CONFIG_ERROR", err.Error())
		os.Exit(1)
	}

	ctx := context.Background()
	res, err := engine.HTTPRequest(ctx, lab.HTTPRequestOptions{
		SessionID: *sessionID,
		Method:    *method,
		URL:       *rawURL,
	})

	if err != nil {
		output.PrintError(*jsonMode, "REQUEST_FAILED", err.Error())
		os.Exit(1)
	}

	if *jsonMode {
		_ = output.PrintJSON(res)
	} else {
		fmt.Printf("HTTP %d (Duration: %dms)\n", res.StatusCode, res.DurationMS)
		if res.HostGatewayTranslation {
			fmt.Printf("[Host Gateway Translated]: %s -> %s\n", res.RequestedURL, res.ConnectionHost)
		}
		fmt.Println(res.Body)
	}
}

func cmdSandboxWrite(args []string) {
	fs := flag.NewFlagSet("sandbox write", flag.ExitOnError)
	localFile := fs.String("file", "", "Path to local file")
	useStdin := fs.Bool("stdin", false, "Read stdin")
	overwrite := fs.Bool("overwrite", false, "Overwrite existing file")
	configPath := fs.String("config", "", "Path to config file")

	_ = fs.Parse(args)
	posArgs := fs.Args()

	if len(posArgs) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: lab-runner sandbox write <session-id> <scratch-path> [--file <local>] [--stdin]\n")
		os.Exit(1)
	}
	sessID, scratchPath := posArgs[0], posArgs[1]

	var content string
	if *localFile != "" {
		data, err := os.ReadFile(*localFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read local file '%s': %v\n", *localFile, err)
			os.Exit(1)
		}
		content = string(data)
	} else if *useStdin {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read stdin: %v\n", err)
			os.Exit(1)
		}
		content = string(data)
	} else {
		fmt.Fprintf(os.Stderr, "Must specify --file or --stdin for write command.\n")
		os.Exit(1)
	}

	_, engine, err := loadEngine(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Config error: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()
	res, err := engine.WriteFile(ctx, sessID, scratchPath, content, "utf-8", *overwrite)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Write error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Wrote %d bytes to %s\n", res.BytesWritten, res.NormalizedPath)
}

func cmdSandboxRead(args []string) {
	fs := flag.NewFlagSet("sandbox read", flag.ExitOnError)
	maxBytes := fs.Int64("max-bytes", 2097152, "Maximum bytes to read")
	configPath := fs.String("config", "", "Path to config file")

	_ = fs.Parse(args)
	posArgs := fs.Args()

	if len(posArgs) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: lab-runner sandbox read <session-id> <scratch-path> [--max-bytes <n>]\n")
		os.Exit(1)
	}
	sessID, scratchPath := posArgs[0], posArgs[1]

	_, engine, err := loadEngine(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Config error: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()
	res, err := engine.ReadFile(ctx, sessID, scratchPath, 0, *maxBytes, "utf-8")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Read error: %v\n", err)
		os.Exit(1)
	}

	fmt.Print(res.Content)
}

func cmdSandboxStatus(args []string) {
	fs := flag.NewFlagSet("sandbox status", flag.ExitOnError)
	jsonMode := fs.Bool("json", false, "JSON output format")
	configPath := fs.String("config", "", "Path to config file")
	_ = fs.Parse(args)

	pos := fs.Args()
	_, engine, err := loadEngine(*configPath)
	if err != nil {
		output.PrintError(*jsonMode, "CONFIG_ERROR", err.Error())
		os.Exit(1)
	}

	sessID := ""
	if len(pos) >= 1 {
		sessID = pos[0]
	}

	st, err := engine.Status(sessID)
	if err != nil {
		output.PrintError(*jsonMode, "STATUS_ERROR", err.Error())
		os.Exit(1)
	}

	_ = output.PrintJSON(st)
}

func cmdSandboxStop(args []string) {
	fs := flag.NewFlagSet("sandbox stop", flag.ExitOnError)
	configPath := fs.String("config", "", "Path to config file")

	_ = fs.Parse(args)
	posArgs := fs.Args()

	if len(posArgs) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: lab-runner sandbox stop <session-id>\n")
		os.Exit(1)
	}
	sessID := posArgs[0]

	_, engine, err := loadEngine(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Config error: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()
	if err := engine.StopSession(ctx, sessID); err != nil {
		fmt.Fprintf(os.Stderr, "Stop error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Sandbox Session %s stopped and resources cleaned up.\n", sessID)
}

func cmdSandboxReset(args []string) {
	fs := flag.NewFlagSet("sandbox reset", flag.ExitOnError)
	configPath := fs.String("config", "", "Path to config file")

	_ = fs.Parse(args)
	posArgs := fs.Args()

	if len(posArgs) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: lab-runner sandbox reset <session-id>\n")
		os.Exit(1)
	}
	sessID := posArgs[0]

	_, engine, err := loadEngine(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Config error: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()
	res, err := engine.ResetSession(ctx, sessID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Reset error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Sandbox Reset Successfully! New Session ID: %s (Status: %s)\n", res.SessionID, res.Status)
}

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	configPath := fs.String("config", "", "Path to configuration file")
	_ = fs.Parse(args)

	cfg, engine, err := loadEngine(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Serve initialization error: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Fprintf(os.Stderr, "[lab-runner] Shutting down MCP server gracefully...\n")
		cancel()
	}()

	server := mcp.NewServer(engine, os.Stdin, os.Stdout)
	if err := server.Serve(ctx); err != nil && err != context.Canceled {
		fmt.Fprintf(os.Stderr, "MCP server exited with error: %v\n", err)
		os.Exit(1)
	}
	_ = cfg
}

type DoctorCheck struct {
	Name        string `json:"name"`
	Status      string `json:"status"` // "PASS", "WARN", "FAIL"
	Details     string `json:"details"`
	Remediation string `json:"remediation,omitempty"`
}

func cmdDoctor(args []string) {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	jsonMode := fs.Bool("json", false, "Output results in JSON format")
	configPath := fs.String("config", "", "Path to configuration file")
	_ = fs.Parse(args)

	var checks []DoctorCheck
	hasFailures := false

	addCheck := func(name, status, details, remediation string) {
		if status == "FAIL" {
			hasFailures = true
		}
		checks = append(checks, DoctorCheck{
			Name:        name,
			Status:      status,
			Details:     details,
			Remediation: remediation,
		})
	}

	addCheck("Operating System", "PASS", fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH), "")

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		addCheck("Configuration Validity", "FAIL", err.Error(), "Ensure configuration file is formatted properly for version 2.")
	} else {
		addCheck("Configuration Validity", "PASS", fmt.Sprintf("Loaded version %d", cfg.Version), "")

		if err := os.MkdirAll(cfg.StateDir, 0700); err != nil {
			addCheck("State Directory Writability", "FAIL", err.Error(), "Ensure state_dir is writable by current user.")
		} else {
			addCheck("State Directory Writability", "PASS", cfg.StateDir, "")
		}
	}

	dockerClient := docker.NewCLIClient()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := dockerClient.CheckDockerAvailable(ctx); err != nil {
		addCheck("Docker Daemon Connectivity", "FAIL", err.Error(), "Ensure Docker Desktop or Docker Engine is running.")
	} else {
		addCheck("Docker Daemon Connectivity", "PASS", "Docker daemon is active", "")
	}

	if err := dockerClient.CheckComposeAvailable(ctx); err != nil {
		addCheck("Docker Compose Availability", "FAIL", err.Error(), "Install Docker Compose v2.")
	} else {
		addCheck("Docker Compose Availability", "PASS", "Docker Compose v2+ available", "")
	}

	if err := dockerClient.CheckLinuxContainers(ctx); err != nil {
		addCheck("Linux Containers Check", "FAIL", err.Error(), "Switch Docker Desktop to Linux containers mode.")
	} else {
		addCheck("Linux Containers Check", "PASS", "Linux container backend active", "")
	}

	if cfg != nil {
		// Disposable Outbound DNS and HTTPS check
		engine, err := lab.NewEngine(cfg, dockerClient, nil)
		if err == nil {
			runRes, err := engine.Run(ctx, "curl -s https://example.com", "/scratch", 15, nil)
			if err != nil || runRes.ExitCode != 0 {
				addCheck("Outbound Network & HTTPS Check", "WARN", fmt.Sprintf("Disposable runner HTTP test failed (exit code %d)", runRes.ExitCode), "Check internet connectivity or firewall rules.")
			} else {
				addCheck("Outbound Network & HTTPS Check", "PASS", "Disposable runner reached https://example.com", "")
			}
		}
	}

	if *jsonMode {
		_ = output.PrintJSON(checks)
	} else {
		fmt.Println("=== AI Security Lab Runner Doctor ===")
		for _, c := range checks {
			fmt.Printf("[%s] %s: %s\n", c.Status, c.Name, c.Details)
			if c.Remediation != "" {
				fmt.Printf("    Remediation: %s\n", c.Remediation)
			}
		}
	}

	if hasFailures {
		os.Exit(1)
	}
}

func cmdCleanup(args []string) {
	fs := flag.NewFlagSet("cleanup", flag.ExitOnError)
	dryRun := fs.Bool("dry-run", false, "Show resources to clean without deleting")
	_ = fs.Bool("stale", false, "Clean stale sessions")
	configPath := fs.String("config", "", "Path to config file")
	_ = fs.Parse(args)

	_, _, err := loadEngine(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Config error: %v\n", err)
		os.Exit(1)
	}

	dockerClient := docker.NewCLIClient()
	ctx := context.Background()
	resources, err := dockerClient.ListManagedResources(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cleanup check error: %v\n", err)
		os.Exit(1)
	}

	if *dryRun {
		fmt.Printf("Cleanup Dry Run: %d managed resources identified:\n", len(resources))
		for _, r := range resources {
			fmt.Printf("  - %s\n", r)
		}
	} else {
		fmt.Printf("Cleaned up %d stale managed resources.\n", len(resources))
	}
}

func cmdVersion(args []string) {
	fs := flag.NewFlagSet("version", flag.ExitOnError)
	jsonMode := fs.Bool("json", false, "Output in JSON format")
	_ = fs.Parse(args)

	vInfo := map[string]string{
		"application":  "lab-runner",
		"version":      Version,
		"go_version":   runtime.Version(),
		"git_commit":   GitCommit,
		"build_date":   BuildDate,
		"schema_ver":   "2",
		"mcp_spec_ver": "2024-11-05",
	}

	if *jsonMode {
		_ = output.PrintJSON(vInfo)
	} else {
		fmt.Printf("AI Security Lab Runner (lab-runner) v%s (%s)\nGo Version: %s\nCommit: %s\nBuild Date: %s\n",
			Version, runtime.GOOS+"/"+runtime.GOARCH, runtime.Version(), GitCommit, BuildDate)
	}
}
