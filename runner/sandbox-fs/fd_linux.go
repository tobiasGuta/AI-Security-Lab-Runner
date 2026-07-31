//go:build !windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func openScratchPathFd(targetPath string, flags int, perm os.FileMode) (*os.File, string, error) {
	if targetPath == "" {
		return nil, "", fmt.Errorf("path is empty")
	}

	cleaned := filepath.Clean(targetPath)
	if !strings.HasPrefix(cleaned, scratchRoot) {
		return nil, "", fmt.Errorf("path '%s' is not beneath '%s'", targetPath, scratchRoot)
	}

	rel, err := filepath.Rel(scratchRoot, cleaned)
	if err != nil {
		return nil, "", fmt.Errorf("failed to evaluate relative path: %w", err)
	}

	if rel == "." {
		f, err := os.OpenFile(scratchRoot, flags, perm)
		return f, scratchRoot, err
	}

	parts := strings.Split(rel, string(filepath.Separator))
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
