package docker

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func fakeDockerExec(t *testing.T, script string) *CLIClient {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Unix shell fixture")
	}
	bin := filepath.Join(t.TempDir(), "fake-docker")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"+script+"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	return &CLIClient{dockerBin: bin}
}

func runFakeDockerExec(t *testing.T, c *CLIClient, maxOutput int64) (int, string, string, bool, bool, bool, error) {
	t.Helper()
	return c.ExecArgvWithInputInRunner(context.Background(), "project", "compose.yaml", "/scratch", []string{"command"}, nil, nil, time.Second*5, maxOutput)
}

func TestDockerExecIndependentOutputLimits(t *testing.T) {
	tests := []struct {
		name       string
		stdout     string
		stderr     string
		limit      int64
		exitCode   int
		wantOut    string
		wantErr    string
		wantOutCut bool
		wantErrCut bool
	}{
		{"stderr only", "", strings.Repeat("E", 128), 16, 0, "", strings.Repeat("E", 16), false, true},
		{"stdout only", strings.Repeat("O", 128), "", 16, 0, strings.Repeat("O", 16), "", true, false},
		{"both", strings.Repeat("O", 128), strings.Repeat("E", 128), 16, 0, strings.Repeat("O", 16), strings.Repeat("E", 16), true, true},
		{"exact boundary", "12345678", "abcdefgh", 8, 0, "12345678", "abcdefgh", false, false},
		{"small output", "ok", "warn", 64, 0, "ok", "warn", false, false},
		{"nonzero exit", "ok", strings.Repeat("E", 20), 8, 9, "ok", strings.Repeat("E", 8), false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			script := "printf '%s' '" + tt.stdout + "'\nprintf '%s' '" + tt.stderr + "' >&2\n"
			if tt.exitCode != 0 {
				script += "exit 9\n"
			}
			c := fakeDockerExec(t, script)
			exit, out, serr, timedOut, outCut, errCut, err := runFakeDockerExec(t, c, tt.limit)
			if err != nil || timedOut || exit != tt.exitCode {
				t.Fatalf("exit=%d timedOut=%t err=%v", exit, timedOut, err)
			}
			if out != tt.wantOut || serr != tt.wantErr || outCut != tt.wantOutCut || errCut != tt.wantErrCut {
				t.Fatalf("stdout=%q stderr=%q stdoutCut=%t stderrCut=%t", out, serr, outCut, errCut)
			}
		})
	}
}

func TestDockerExecDefaultLimitIsBounded(t *testing.T) {
	// 1,200 x 1 KiB of stderr, far above the 1 MiB fallback;
	// don't store the payload in the script or test process.
	block := strings.Repeat("Z", 1024)
	script := "i=0\nwhile [ \"$i\" -lt 1200 ]; do\n  printf '%s' '" + block + "' >&2\n  i=$((i+1))\ndone"
	c := fakeDockerExec(t, script)
	exit, out, serr, timedOut, outCut, errCut, err := runFakeDockerExec(t, c, 0)
	if err != nil || exit != 0 || timedOut || outCut || !errCut || out != "" {
		t.Fatalf("unexpected default-limit result: exit=%d timedOut=%t outCut=%t errCut=%t err=%v", exit, timedOut, outCut, errCut, err)
	}
	if len(serr) != int(defaultExecOutputLimit) {
		t.Fatalf("default stderr limit: got %d bytes, want %d", len(serr), defaultExecOutputLimit)
	}
	if strings.Count(serr, "Z") != len(serr) {
		t.Fatal("stderr prefix not preserved")
	}
}

func TestDockerExecBinaryOutputPreservedWhileStderrBounded(t *testing.T) {
	c := fakeDockerExec(t, "printf '\\000\\001\\377'\nprintf '%s' '"+strings.Repeat("E", 80)+"' >&2")
	var binary bytes.Buffer
	exit, serr, timedOut, errCut, err := c.ExecArgvWithBinaryStdoutInRunner(
		context.Background(), "project", "compose.yaml", "/scratch", []string{"command"},
		nil, nil, 5*time.Second, &binary, 12,
	)
	if err != nil || timedOut || exit != 0 {
		t.Fatalf("binary path exit=%d timedOut=%t err=%v", exit, timedOut, err)
	}
	if !bytes.Equal(binary.Bytes(), []byte{0, 1, 255}) {
		t.Fatalf("binary stdout was modified: %v", binary.Bytes())
	}
	if serr != strings.Repeat("E", 12) || !errCut {
		t.Fatalf("binary-path stderr not bounded: %q cut=%t", serr, errCut)
	}
}

func TestDockerExecSystemErrorDoesNotExposeUnboundedOutput(t *testing.T) {
	c := &CLIClient{dockerBin: filepath.Join(t.TempDir(), "does-not-exist")}
	_, out, serr, _, outCut, errCut, err := runFakeDockerExec(t, c, 8)
	if !errors.Is(err, ErrDockerExecFailed) || out != "" || serr != "" || outCut || errCut {
		t.Fatalf("unexpected system failure result: stdout=%q stderr=%q stdoutCut=%t stderrCut=%t err=%v", out, serr, outCut, errCut, err)
	}
}
