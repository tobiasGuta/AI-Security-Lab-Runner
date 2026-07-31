package scratchfs

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

const (
	ScratchRoot        = "/scratch"
	MaxCookieSizeBytes = 1048576 // 1 MiB
)

var (
	ErrInvalidPath     = errors.New("INVALID_INPUT: path is invalid or outside /scratch")
	ErrSymlinkDetected = errors.New("INVALID_INPUT: symlink encountered in path")
	ErrNotRegularFile  = errors.New("INVALID_INPUT: target is not a regular file")
	ErrFileTooLarge    = errors.New("RESPONSE_TOO_LARGE: file exceeds maximum allowed size")
)

// ValidateScratchPath validates that targetPath is strictly beneath /scratch and returns relative parts.
func ValidateScratchPath(targetPath string, requireFile bool) (string, []string, error) {
	if targetPath == "" {
		return "", nil, fmt.Errorf("%w: path is empty", ErrInvalidPath)
	}

	cleaned := filepath.Clean(targetPath)
	if !strings.HasPrefix(cleaned, ScratchRoot) {
		return "", nil, fmt.Errorf("%w: path '%s' is not beneath '%s'", ErrInvalidPath, targetPath, ScratchRoot)
	}

	rel, err := filepath.Rel(ScratchRoot, cleaned)
	if err != nil {
		return "", nil, fmt.Errorf("%w: failed to evaluate relative path: %v", ErrInvalidPath, err)
	}

	if rel == ".." || strings.HasPrefix(rel, "../") || strings.HasPrefix(rel, "..\\") || filepath.IsAbs(rel) {
		return "", nil, fmt.Errorf("%w: path traversal attempt detected in '%s'", ErrInvalidPath, rel)
	}

	if requireFile && (rel == "." || rel == "") {
		return "", nil, fmt.Errorf("%w: path refers to /scratch root, expected regular file descendant", ErrInvalidPath)
	}

	if rel == "." {
		return cleaned, nil, nil
	}

	parts := strings.Split(rel, string(filepath.Separator))
	return cleaned, parts, nil
}

// GenerateTempFileName creates a random temporary filename strictly under /scratch.
func GenerateTempFileName(dir string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	if dir == "" || !strings.HasPrefix(dir, ScratchRoot) {
		dir = ScratchRoot
	}
	return filepath.Join(dir, fmt.Sprintf(".sys_tmp_%s.tmp", hex.EncodeToString(b)))
}
