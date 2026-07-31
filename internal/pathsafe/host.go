package pathsafe

import (
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"unicode"
)

var (
	ErrInvalidPath     = errors.New("invalid path")
	ErrOutsideRoot     = errors.New("path outside allowed root")
	ErrReservedName    = errors.New("reserved filename")
	ErrUnsupportedPath = errors.New("unsupported path format")
)

// Reserved Windows file names.
var reservedNames = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true,
	"COM1": true, "COM2": true, "COM3": true, "COM4": true, "COM5": true, "COM6": true, "COM7": true, "COM8": true, "COM9": true,
	"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true, "LPT5": true, "LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
}

// Invariant 9: All host paths remain inside configured roots.
// CleanHostPath validates and canonicalizes a host path.
func CleanHostPath(p string) (string, error) {
	if p == "" {
		return "", fmt.Errorf("%w: path is empty", ErrInvalidPath)
	}

	// Check null bytes or control characters
	for _, r := range p {
		if r == 0 || unicode.IsControl(r) {
			return "", fmt.Errorf("%w: path contains control characters or null bytes", ErrInvalidPath)
		}
	}

	// Check UNC or device paths on Windows
	if strings.HasPrefix(p, `\\`) || strings.HasPrefix(p, `//`) {
		return "", fmt.Errorf("%w: UNC or device paths are not allowed", ErrUnsupportedPath)
	}

	cleaned := filepath.Clean(p)

	// Check Windows reserved names
	base := filepath.Base(cleaned)
	ext := filepath.Ext(base)
	stem := strings.ToUpper(strings.TrimSuffix(base, ext))
	if reservedNames[stem] {
		return "", fmt.Errorf("%w: '%s' is a reserved device name", ErrReservedName, base)
	}

	// Reject trailing spaces or dots in path components on Windows
	if runtime.GOOS == "windows" {
		parts := strings.Split(cleaned, string(filepath.Separator))
		for _, part := range parts {
			if strings.HasSuffix(part, " ") || strings.HasSuffix(part, ".") {
				if part != "." && part != ".." {
					return "", fmt.Errorf("%w: path component has trailing dot or space", ErrInvalidPath)
				}
			}
		}
	}

	return cleaned, nil
}

// ValidateHostPathUnderRoot ensures that 'targetPath' resolves to a location inside 'rootPath'.
// It resolves symbolic links for existing paths/parents and enforces containment.
func ValidateHostPathUnderRoot(targetPath, rootPath string) (string, error) {
	cleanRoot, err := CleanHostPath(rootPath)
	if err != nil {
		return "", fmt.Errorf("invalid root path: %w", err)
	}

	absRoot, err := filepath.Abs(cleanRoot)
	if err != nil {
		return "", fmt.Errorf("failed to get absolute root path: %w", err)
	}

	// Resolve symlinks on root if it exists
	if resolvedRoot, err := filepath.EvalSymlinks(absRoot); err == nil {
		absRoot = resolvedRoot
	}

	cleanTarget, err := CleanHostPath(targetPath)
	if err != nil {
		return "", fmt.Errorf("invalid target path: %w", err)
	}

	absTarget, err := filepath.Abs(cleanTarget)
	if err != nil {
		return "", fmt.Errorf("failed to get absolute target path: %w", err)
	}

	// If target exists, resolve symlinks directly
	var resolvedTarget string
	if resolved, err := filepath.EvalSymlinks(absTarget); err == nil {
		resolvedTarget = resolved
	} else {
		// If target does not exist, resolve parent directory symlinks
		parent := filepath.Dir(absTarget)
		if resolvedParent, err := filepath.EvalSymlinks(parent); err == nil {
			resolvedTarget = filepath.Join(resolvedParent, filepath.Base(absTarget))
		} else {
			resolvedTarget = absTarget
		}
	}

	if !isSubpath(resolvedTarget, absRoot) {
		return "", fmt.Errorf("%w: '%s' is not under root '%s'", ErrOutsideRoot, targetPath, rootPath)
	}

	return resolvedTarget, nil
}

func isSubpath(target, root string) bool {
	t := filepath.Clean(target)
	r := filepath.Clean(root)

	if runtime.GOOS == "windows" {
		t = strings.ToLower(t)
		r = strings.ToLower(r)
	}

	if t == r {
		return true
	}

	if !strings.HasSuffix(r, string(filepath.Separator)) {
		r += string(filepath.Separator)
	}

	return strings.HasPrefix(t, r)
}
