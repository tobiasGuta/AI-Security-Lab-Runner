//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

	if rel == ".." || strings.HasPrefix(rel, "../") || strings.HasPrefix(rel, "..\\") || filepath.IsAbs(rel) {
		return nil, "", fmt.Errorf("path traversal attempt detected in '%s'", rel)
	}

	f, err := os.OpenFile(cleaned, flags, perm)
	if err != nil {
		return nil, "", err
	}
	return f, cleaned, nil
}

func mkdiratScratchPath(targetPath string) error {
	cleaned := filepath.Clean(targetPath)
	dir := filepath.Dir(cleaned)
	if !strings.HasPrefix(dir, scratchRoot) {
		return fmt.Errorf("directory outside /scratch")
	}
	return os.MkdirAll(dir, 0755)
}
