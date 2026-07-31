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
	"syscall"
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

func cmdRead(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: sandbox-fs read <path> [offset] [maxBytes]\n")
		os.Exit(1)
	}

	p := args[0]
	f, cleanPath, err := openScratchPathFd(p, syscall.O_RDONLY, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Security Violation: %v\n", err)
		os.Exit(2)
	}
	defer f.Close()

	info, err := f.Stat()
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
		if val, err := strconv.ParseInt(args[1], 10, 64); err == nil && val >= 0 {
			offset = val
		}
	}
	if len(args) >= 3 {
		if val, err := strconv.ParseInt(args[2], 10, 64); err == nil && val > 0 {
			maxBytes = val
		}
	}

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

	cleaned := filepath.Clean(p)
	if !strings.HasPrefix(cleaned, scratchRoot) || cleaned == scratchRoot {
		fmt.Fprintf(os.Stderr, "Security Violation: path '%s' invalid\n", p)
		os.Exit(2)
	}

	if err := mkdiratScratchPath(cleaned); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create parent directories: %v\n", err)
		os.Exit(1)
	}

	var flags int
	if overwrite {
		flags = syscall.O_CREAT | syscall.O_WRONLY | syscall.O_TRUNC
	} else {
		flags = syscall.O_CREAT | syscall.O_WRONLY | syscall.O_EXCL
	}

	f, cleanPath, err := openScratchPathFd(cleaned, flags, 0644)
	if err != nil {
		if os.IsExist(err) || strings.Contains(err.Error(), "exist") {
			fmt.Fprintf(os.Stderr, "Error: file '%s' already exists and overwrite is false\n", cleaned)
			os.Exit(17)
		}
		fmt.Fprintf(os.Stderr, "Security Violation: %v\n", err)
		os.Exit(2)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		fmt.Fprintf(os.Stderr, "Error: '%s' is not a regular file\n", cleanPath)
		os.Exit(2)
	}

	n, err := io.Copy(f, os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write payload: %v\n", err)
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
	f, cleanPath, err := openScratchPathFd(p, syscall.O_RDONLY, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Security Violation: %v\n", err)
		os.Exit(2)
	}
	defer f.Close()

	info, err := f.Stat()
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
	f, cleanPath, err := openScratchPathFd(p, syscall.O_RDONLY, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Security Violation: %v\n", err)
		os.Exit(2)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		fmt.Fprintf(os.Stderr, "Error: '%s' is not a regular file\n", cleanPath)
		os.Exit(2)
	}

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to compute hash: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(hex.EncodeToString(h.Sum(nil)))
}
