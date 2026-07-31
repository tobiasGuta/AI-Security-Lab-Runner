package pathsafe

import (
	"fmt"
	"path"
	"strings"
	"unicode"
)

// Invariant 10: All container paths remain inside their allowed roots.
// CleanContainerPath cleans a container path using POSIX rules.
func CleanContainerPath(p string) (string, error) {
	if p == "" {
		return "", fmt.Errorf("%w: container path is empty", ErrInvalidPath)
	}

	for _, r := range p {
		if r == 0 || unicode.IsControl(r) {
			return "", fmt.Errorf("%w: container path contains control characters or null bytes", ErrInvalidPath)
		}
	}

	// Normalize backslashes to forward slashes for POSIX consistency
	p = strings.ReplaceAll(p, "\\", "/")
	cleaned := path.Clean(p)

	if !strings.HasPrefix(cleaned, "/") {
		cleaned = "/" + cleaned
	}

	return cleaned, nil
}

// ValidateContainerPathUnderAllowed validates that container path is inside one of allowed roots (e.g. /workspace, /scratch).
func ValidateContainerPathUnderAllowed(p string, allowedRoots []string) (string, error) {
	cleaned, err := CleanContainerPath(p)
	if err != nil {
		return "", err
	}

	for _, root := range allowedRoots {
		cleanRoot, err := CleanContainerPath(root)
		if err != nil {
			continue
		}

		if isContainerSubpath(cleaned, cleanRoot) {
			return cleaned, nil
		}
	}

	return "", fmt.Errorf("%w: container path '%s' is not within allowed roots %v", ErrOutsideRoot, p, allowedRoots)
}

func isContainerSubpath(target, root string) bool {
	t := path.Clean(target)
	r := path.Clean(root)

	if t == r {
		return true
	}

	if !strings.HasSuffix(r, "/") {
		r += "/"
	}

	return strings.HasPrefix(t, r)
}
