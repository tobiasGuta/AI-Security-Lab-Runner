//go:build !windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func validateScratchRelPath(targetPath string, requireFile bool) (string, []string, error) {
	if targetPath == "" {
		return "", nil, fmt.Errorf("path is empty")
	}

	cleaned := filepath.Clean(targetPath)
	if !strings.HasPrefix(cleaned, scratchRoot) {
		return "", nil, fmt.Errorf("path '%s' is not beneath '%s'", targetPath, scratchRoot)
	}

	rel, err := filepath.Rel(scratchRoot, cleaned)
	if err != nil {
		return "", nil, fmt.Errorf("failed to evaluate relative path: %w", err)
	}

	if rel == ".." || strings.HasPrefix(rel, "../") || strings.HasPrefix(rel, "..\\") || filepath.IsAbs(rel) {
		return "", nil, fmt.Errorf("path traversal attempt detected in '%s'", rel)
	}

	if requireFile && (rel == "." || rel == "") {
		return "", nil, fmt.Errorf("path '%s' refers to /scratch root, expected regular file descendant", targetPath)
	}

	if rel == "." {
		return cleaned, nil, nil
	}

	parts := strings.Split(rel, string(filepath.Separator))
	return cleaned, parts, nil
}

func openScratchPathFd(targetPath string, flags int, perm os.FileMode) (*os.File, string, error) {
	cleaned, parts, err := validateScratchRelPath(targetPath, false)
	if err != nil {
		return nil, "", err
	}

	if len(parts) == 0 {
		f, err := os.OpenFile(scratchRoot, flags, perm)
		return f, scratchRoot, err
	}

	dirFd, err := syscall.Open(scratchRoot, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY, 0)
	if err != nil {
		return nil, "", fmt.Errorf("failed to open scratch root descriptor: %w", err)
	}
	defer syscall.Close(dirFd)

	currFd := dirFd
	for i, part := range parts {
		isLast := i == len(parts)-1
		var mode int
		if isLast {
			mode = flags | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
		} else {
			mode = syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
		}

		nextFd, err := syscall.Openat(currFd, part, mode, uint32(perm))
		if err != nil {
			if err == syscall.ELOOP || err == syscall.EMLINK {
				return nil, "", fmt.Errorf("symlink encountered during descriptor traversal for component '%s'", part)
			}
			return nil, "", fmt.Errorf("failed descriptor-relative open for '%s': %w", part, err)
		}

		if !isLast {
			if currFd != dirFd {
				syscall.Close(currFd)
			}
			currFd = nextFd
		} else {
			if currFd != dirFd {
				syscall.Close(currFd)
			}
			return os.NewFile(uintptr(nextFd), cleaned), cleaned, nil
		}
	}

	return nil, "", fmt.Errorf("descriptor traversal error")
}

// mkdiratScratchPath creates intermediate directories descriptor-relatively using mkdirat.
func mkdiratScratchPath(targetPath string) error {
	_, parts, err := validateScratchRelPath(targetPath, false)
	if err != nil || len(parts) <= 1 {
		return err
	}

	dirParts := parts[:len(parts)-1]

	dirFd, err := syscall.Open(scratchRoot, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(dirFd)

	currFd := dirFd
	for _, part := range dirParts {
		// Attempt mkdirat
		_ = syscall.Mkdirat(currFd, part, 0755)

		nextFd, err := syscall.Openat(currFd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			if currFd != dirFd {
				syscall.Close(currFd)
			}
			return fmt.Errorf("failed directory component descriptor open '%s': %w", part, err)
		}

		if currFd != dirFd {
			syscall.Close(currFd)
		}
		currFd = nextFd
	}

	if currFd != dirFd {
		syscall.Close(currFd)
	}
	return nil
}
