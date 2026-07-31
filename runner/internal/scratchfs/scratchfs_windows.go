//go:build windows

package scratchfs

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func OpenScratchFd(targetPath string, flags int, perm os.FileMode) (*os.File, string, error) {
	cleaned, _, err := ValidateScratchPath(targetPath, false)
	if err != nil {
		return nil, "", err
	}

	f, err := os.OpenFile(cleaned, flags, perm)
	if err != nil {
		return nil, "", err
	}
	return f, cleaned, nil
}

func MkdiratScratch(targetPath string) error {
	cleaned, _, err := ValidateScratchPath(targetPath, false)
	if err != nil {
		return err
	}
	dir := filepath.Dir(cleaned)
	return os.MkdirAll(dir, 0755)
}

func SaveCookieFileAtomic(cookiePath string, data []byte) error {
	cleaned, _, err := ValidateScratchPath(cookiePath, true)
	if err != nil {
		return err
	}
	if len(data) > MaxCookieSizeBytes {
		return ErrFileTooLarge
	}
	dir := filepath.Dir(cleaned)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	tmp := GenerateTempFileName(dir)
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, cleaned)
}

func LoadCookieFileSecure(cookiePath string) ([]byte, error) {
	cleaned, _, err := ValidateScratchPath(cookiePath, true)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(cleaned)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: '%s' is not a regular file", ErrNotRegularFile, cleaned)
	}
	if info.Size() > MaxCookieSizeBytes {
		return nil, ErrFileTooLarge
	}

	return io.ReadAll(io.LimitReader(f, MaxCookieSizeBytes))
}
