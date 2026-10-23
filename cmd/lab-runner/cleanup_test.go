package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/lab"
	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/session"
)

func TestPrintCleanupReport(t *testing.T) {
	tests := []struct {
		name       string
		dry        bool
		results    []lab.StaleCleanupResult
		wantCode   int
		wantOut    string
		wantErr    string
		forbidText string
	}{
		{
			name: "dry run never claims removal",
			dry:  true,
			results: []lab.StaleCleanupResult{
				{SessionID: "stale-session", PriorStatus: session.StateExpired, DryRun: true},
			},
			wantOut:    "no resources removed",
			forbidText: "Cleaned session",
		},
		{
			name: "verified cleanup",
			results: []lab.StaleCleanupResult{
				{SessionID: "stale-session", Cleaned: true},
			},
			wantOut: "1 verified cleaned, 0 failed",
		},
		{
			name: "cleanup failure produces nonzero status",
			results: []lab.StaleCleanupResult{
				{SessionID: "stale-session", Error: "Docker daemon unavailable"},
			},
			wantCode:   1,
			wantOut:    "0 verified cleaned, 1 failed",
			wantErr:    "FAILED cleanup stale-session",
			forbidText: "Cleaned session stale-session",
		},
		{
			name: "unverified absence cannot count as clean",
			results: []lab.StaleCleanupResult{
				{SessionID: "stale-session"},
			},
			wantCode: 1,
			wantErr:  "resource absence was not verified",
		},
		{
			name:    "no candidates",
			wantOut: "0 verified cleaned, 0 failed, 0 stale candidate(s)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := printCleanupReport(tt.results, tt.dry, &stdout, &stderr)
			if code != tt.wantCode {
				t.Fatalf("exit code %d, want %d; stdout=%q stderr=%q", code, tt.wantCode, stdout.String(), stderr.String())
			}
			if !strings.Contains(stdout.String(), tt.wantOut) {
				t.Errorf("stdout missing %q: %q", tt.wantOut, stdout.String())
			}
			if !strings.Contains(stderr.String(), tt.wantErr) {
				t.Errorf("stderr missing %q: %q", tt.wantErr, stderr.String())
			}
			if tt.forbidText != "" && (strings.Contains(stdout.String(), tt.forbidText) || strings.Contains(stderr.String(), tt.forbidText)) {
				t.Errorf("unexpected text %q: stdout=%q stderr=%q", tt.forbidText, stdout.String(), stderr.String())
			}
		})
	}
}
