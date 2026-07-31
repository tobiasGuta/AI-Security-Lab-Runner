package pathsafe

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCleanHostPath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"valid path", "foo/bar", false},
		{"empty path", "", true},
		{"null byte", "foo\x00bar", true},
		{"reserved CON", "CON.txt", true},
		{"reserved NUL", "nul", true},
		{"UNC path", `\\server\share\file`, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := CleanHostPath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("CleanHostPath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
		})
	}
}

func TestValidateHostPathUnderRoot(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "pathsafe_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	subDir := filepath.Join(tempDir, "sub")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatal(err)
	}

	validFile := filepath.Join(subDir, "file.txt")
	if err := os.WriteFile(validFile, []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}

	escapedFile := filepath.Join(tempDir, "..", "outside.txt")

	// Valid path inside root
	if _, err := ValidateHostPathUnderRoot(validFile, tempDir); err != nil {
		t.Errorf("expected valid file under root, got error: %v", err)
	}

	// Escaped path
	if _, err := ValidateHostPathUnderRoot(escapedFile, subDir); err == nil {
		t.Errorf("expected error for path outside root, got nil")
	}

	// Symlink escape test
	if runtime.GOOS != "windows" {
		symlinkTarget := filepath.Join(tempDir, "symlink_outside")
		outsideDir, _ := os.MkdirTemp("", "outside_dir_*")
		defer os.RemoveAll(outsideDir)

		_ = os.Symlink(outsideDir, symlinkTarget)
		if _, err := ValidateHostPathUnderRoot(filepath.Join(symlinkTarget, "file.txt"), tempDir); err == nil {
			t.Errorf("expected error for symlink target outside root, got nil")
		}
	}
}

func TestContainerPathValidation(t *testing.T) {
	allowed := []string{"/workspace", "/scratch"}

	tests := []struct {
		path    string
		wantErr bool
	}{
		{"/workspace/src/index.js", false},
		{"/scratch/script.py", false},
		{"/workspace/../scratch/test", false}, // cleans to /scratch/test which is allowed
		{"/etc/passwd", true},
		{"/workspace/../../etc/passwd", true},
		{"/scratch/foo/bar/baz.json", false},
		{"", true},
		{"/workspace\x00bad", true},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			_, err := ValidateContainerPathUnderAllowed(tt.path, allowed)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateContainerPathUnderAllowed(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
		})
	}
}
