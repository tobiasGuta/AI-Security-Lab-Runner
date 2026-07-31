package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const scratchRoot = "/scratch"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: sandbox-fs read|write|stat|hash <path> [args...]\n")
		os.Exit(1)
	}

	subcommand := os.Args[1]
	switch subcommand {
	case "read":
		cmdRead(os.Args[2:])
	case "write":
		cmdWrite(os.Args[2:])
	case "stat":
		cmdStat(os.Args[2:])
	case "hash":
		cmdHash(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown subcommand: %s\n", subcommand)
		os.Exit(1)
	}
}

// validateScratchPath checks that target is within /scratch without escaping through symlinks.
func validateScratchPath(p string) (string, error) {
	if p == "" {
		return "", fmt.Errorf("path is empty")
	}

	cleaned := filepath.Clean(p)
	if !strings.HasPrefix(cleaned, scratchRoot) {
		return "", fmt.Errorf("path '%s' is not beneath '%s'", p, scratchRoot)
	}

	// Lstat each component starting from scratchRoot
	rel, err := filepath.Rel(scratchRoot, cleaned)
	if err != nil {
		return "", fmt.Errorf("failed to evaluate relative path: %w", err)
	}

	if rel == "." {
		return scratchRoot, nil
	}

	parts := strings.Split(rel, string(filepath.Separator))
	curr := scratchRoot
	for _, part := range parts {
		curr = filepath.Join(curr, part)
		info, err := os.Lstat(curr)
		if err != nil {
			if os.IsNotExist(err) {
				// Path component doesn't exist yet (okay for write)
				break
			}
			return "", fmt.Errorf("lstat failed for component '%s': %w", curr, err)
		}

		if info.Mode()&os.ModeSymlink != 0 {
			// Resolve symlink target
			target, err := os.Readlink(curr)
			if err != nil {
				return "", fmt.Errorf("failed to read symlink '%s': %w", curr, err)
			}

			var resolvedTarget string
			if filepath.IsAbs(target) {
				resolvedTarget = filepath.Clean(target)
			} else {
				resolvedTarget = filepath.Clean(filepath.Join(filepath.Dir(curr), target))
			}

			if !strings.HasPrefix(resolvedTarget, scratchRoot) {
				return "", fmt.Errorf("symlink '%s' points outside /scratch to '%s'", curr, resolvedTarget)
			}
		}

		if info.Mode()&(os.ModeDevice|os.ModeSocket|os.ModeNamedPipe|os.ModeCharDevice) != 0 {
			return "", fmt.Errorf("path '%s' is an unsupported special file", curr)
		}
	}

	return cleaned, nil
}

func cmdRead(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: sandbox-fs read <path> [offset] [maxBytes]\n")
		os.Exit(1)
	}

	p := args[0]
	cleanPath, err := validateScratchPath(p)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Security Violation: %v\n", err)
		os.Exit(2)
	}

	info, err := os.Lstat(cleanPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "File not found: %v\n", err)
		os.Exit(1)
	}

	if !info.Mode().IsRegular() {
		fmt.Fprintf(os.Stderr, "Error: '%s' is not a regular file\n", cleanPath)
		os.Exit(2)
	}

	var offset int64 = 0
	var maxBytes int64 = 2097152

	if len(args) >= 2 {
		if val, err := strconv.ParseInt(args[1], 10, 64); err == nil {
			offset = val
		}
	}
	if len(args) >= 3 {
		if val, err := strconv.ParseInt(args[2], 10, 64); err == nil {
			maxBytes = val
		}
	}

	f, err := os.Open(cleanPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to seek offset: %v\n", err)
			os.Exit(1)
		}
	}

	lr := io.LimitReader(f, maxBytes)
	if _, err := io.Copy(os.Stdout, lr); err != nil {
		fmt.Fprintf(os.Stderr, "Read error: %v\n", err)
		os.Exit(1)
	}
}

func cmdWrite(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: sandbox-fs write <path> [overwrite]\n")
		os.Exit(1)
	}

	p := args[0]
	overwrite := false
	if len(args) >= 2 && (args[1] == "true" || args[1] == "1") {
		overwrite = true
	}

	cleanPath, err := validateScratchPath(p)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Security Violation: %v\n", err)
		os.Exit(2)
	}

	if cleanPath == scratchRoot || cleanPath == scratchRoot+"/" {
		fmt.Fprintf(os.Stderr, "Error: cannot write directly to /scratch as a file\n")
		os.Exit(2)
	}

	dir := filepath.Dir(cleanPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create directory: %v\n", err)
		os.Exit(1)
	}

	// Check existing target
	if info, err := os.Lstat(cleanPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			fmt.Fprintf(os.Stderr, "Security Violation: cannot overwrite symbolic link '%s'\n", cleanPath)
			os.Exit(2)
		}
		if !info.Mode().IsRegular() {
			fmt.Fprintf(os.Stderr, "Error: '%s' is not a regular file\n", cleanPath)
			os.Exit(2)
		}
		if !overwrite {
			fmt.Fprintf(os.Stderr, "Error: file '%s' already exists and overwrite is false\n", cleanPath)
			os.Exit(17)
		}
	}

	tmpFile := cleanPath + ".tmp"
	f, err := os.OpenFile(tmpFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create temporary file: %v\n", err)
		os.Exit(1)
	}

	n, err := io.Copy(f, os.Stdin)
	_ = f.Close()
	if err != nil {
		_ = os.Remove(tmpFile)
		fmt.Fprintf(os.Stderr, "Failed to write file payload: %v\n", err)
		os.Exit(1)
	}

	if err := os.Rename(tmpFile, cleanPath); err != nil {
		_ = os.Remove(tmpFile)
		fmt.Fprintf(os.Stderr, "Failed to move file atomically: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("%d\n", n)
}

func cmdStat(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: sandbox-fs stat <path>\n")
		os.Exit(1)
	}

	p := args[0]
	cleanPath, err := validateScratchPath(p)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Security Violation: %v\n", err)
		os.Exit(2)
	}

	info, err := os.Lstat(cleanPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Stat error: %v\n", err)
		os.Exit(1)
	}

	statObj := map[string]interface{}{
		"path":          cleanPath,
		"size":          info.Size(),
		"mode":          info.Mode().String(),
		"is_dir":        info.IsDir(),
		"is_regular":    info.Mode().IsRegular(),
		"is_symlink":    info.Mode()&os.ModeSymlink != 0,
		"mod_time_unix": info.ModTime().Unix(),
	}

	data, _ := json.Marshal(statObj)
	fmt.Println(string(data))
}

func cmdHash(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: sandbox-fs hash <path>\n")
		os.Exit(1)
	}

	p := args[0]
	cleanPath, err := validateScratchPath(p)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Security Violation: %v\n", err)
		os.Exit(2)
	}

	info, err := os.Lstat(cleanPath)
	if err != nil || !info.Mode().IsRegular() {
		fmt.Fprintf(os.Stderr, "Error: '%s' is not a regular file\n", cleanPath)
		os.Exit(2)
	}

	f, err := os.Open(cleanPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to compute hash: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(hex.EncodeToString(h.Sum(nil)))
}
