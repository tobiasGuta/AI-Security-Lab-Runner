//go:build !windows

package scratchfs

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// OpenScratchFd opens a file strictly beneath /scratch using descriptor-relative openat traversal with O_NOFOLLOW.
func OpenScratchFd(targetPath string, flags int, perm os.FileMode) (*os.File, string, error) {
	cleaned, parts, err := ValidateScratchPath(targetPath, false)
	if err != nil {
		return nil, "", err
	}

	if len(parts) == 0 {
		f, err := os.OpenFile(ScratchRoot, flags, perm)
		return f, ScratchRoot, err
	}

	dirFd, err := syscall.Open(ScratchRoot, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY, 0)
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
			if currFd != dirFd {
				syscall.Close(currFd)
			}
			if err == syscall.ELOOP || err == syscall.EMLINK {
				return nil, "", fmt.Errorf("%w: symlink encountered during descriptor traversal for component '%s'", ErrSymlinkDetected, part)
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

// MkdiratScratch creates parent directories descriptor-relatively using mkdirat starting from open /scratch descriptor.
func MkdiratScratch(targetPath string) error {
	_, parts, err := ValidateScratchPath(targetPath, false)
	if err != nil || len(parts) <= 1 {
		return err
	}

	dirParts := parts[:len(parts)-1]

	dirFd, err := syscall.Open(ScratchRoot, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(dirFd)

	currFd := dirFd
	for _, part := range dirParts {
		_ = syscall.Mkdirat(currFd, part, 0755)

		nextFd, err := syscall.Openat(currFd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			if currFd != dirFd {
				syscall.Close(currFd)
			}
			return fmt.Errorf("failed directory component openat '%s': %w", part, err)
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

// SaveCookieFileAtomic saves cookie data descriptor-relatively using a temporary file and renameat.
func SaveCookieFileAtomic(cookiePath string, data []byte) error {
	cleaned, parts, err := ValidateScratchPath(cookiePath, true)
	if err != nil {
		return err
	}

	if len(data) > MaxCookieSizeBytes {
		return ErrFileTooLarge
	}

	if err := MkdiratScratch(cleaned); err != nil {
		return fmt.Errorf("failed to create parent directory descriptor-relatively: %w", err)
	}

	parentDir := ScratchRoot
	if len(parts) > 1 {
		parentDir = filepath.Join(ScratchRoot, filepath.Join(parts[:len(parts)-1]...))
	}
	targetName := parts[len(parts)-1]

	// Open parent directory descriptor
	parentFd, _, err := OpenScratchFd(parentDir, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("failed to open parent directory descriptor: %w", err)
	}
	defer parentFd.Close()

	tempPath := GenerateTempFileName(parentDir)
	tempName := filepath.Base(tempPath)

	// Create temp file descriptor-relatively with mode 0600
	tempFd, err := syscall.Openat(int(parentFd.Fd()), tempName, syscall.O_CREAT|syscall.O_WRONLY|syscall.O_EXCL|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create temp cookie file descriptor-relatively: %w", err)
	}
	tempFile := os.NewFile(uintptr(tempFd), tempPath)

	if _, err := tempFile.Write(data); err != nil {
		_ = tempFile.Close()
		_ = syscall.Unlinkat(int(parentFd.Fd()), tempName)
		return fmt.Errorf("failed to write cookie data: %w", err)
	}

	_ = tempFile.Sync()
	_ = tempFile.Close()

	// Renameat inside open parent directory descriptor
	if err := syscall.Renameat(int(parentFd.Fd()), tempName, int(parentFd.Fd()), targetName); err != nil {
		_ = syscall.Unlinkat(int(parentFd.Fd()), tempName)
		return fmt.Errorf("failed to rename temp cookie file descriptor-relatively: %w", err)
	}

	return nil
}

// LoadCookieFileSecure loads cookie data descriptor-relatively with 1 MiB size limit and O_NOFOLLOW.
func LoadCookieFileSecure(cookiePath string) ([]byte, error) {
	f, cleanPath, err := OpenScratchFd(cookiePath, syscall.O_RDONLY, 0)
	if err != nil {
		if os.IsNotExist(err) || strings.Contains(err.Error(), "no such file") {
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
		return nil, fmt.Errorf("%w: '%s' is not a regular file", ErrNotRegularFile, cleanPath)
	}

	if info.Size() > MaxCookieSizeBytes {
		return nil, ErrFileTooLarge
	}

	lr := io.LimitReader(f, MaxCookieSizeBytes+1)
	data, err := io.ReadAll(lr)
	if err != nil {
		return nil, err
	}

	if int64(len(data)) > MaxCookieSizeBytes {
		return nil, ErrFileTooLarge
	}

	return data, nil
}
