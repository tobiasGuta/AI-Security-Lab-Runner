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

	f, err := os.OpenFile(cleaned, flags, perm)
	if err != nil {
		return nil, "", err
	}
	return f, cleaned, nil
}
