package lab

import (
	"context"
	"testing"
	"time"

	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/config"
)

type stderrOnlyTruncationDocker struct {
	MockDockerClient
}

func (d *stderrOnlyTruncationDocker) ExecInRunner(ctx context.Context, projectName, composeFilePath, cwd, cmd string, env map[string]string, timeout time.Duration, maxOutputBytes int64) (int, string, string, bool, bool, bool, error) {
	return 0, "ordinary stdout", "bounded stderr", false, false, true, nil
}

func TestEngineTruncationFlagsAreIndependent(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.StateDir = t.TempDir()
	eng, err := NewEngine(cfg, &stderrOnlyTruncationDocker{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	start, err := eng.StartSession(context.Background(), nil, nil, 60)
	if err != nil {
		t.Fatal(err)
	}

	persistent, err := eng.Exec(context.Background(), start.SessionID, "printf hello", "/scratch", 5, nil)
	if err != nil {
		t.Fatal(err)
	}
	if persistent.StdoutTruncated || !persistent.StderrTruncated {
		t.Fatalf("persistent flags not independently reported: %+v", persistent)
	}
	if persistent.Stdout != "ordinary stdout" || persistent.Stderr != "bounded stderr" {
		t.Fatalf("persistent stream contents changed: %+v", persistent)
	}

	oneShot, err := eng.Run(context.Background(), "printf hello", "/scratch", 5, nil)
	if err != nil {
		t.Fatal(err)
	}
	if oneShot.StdoutTruncated || !oneShot.StderrTruncated {
		t.Fatalf("one-shot flags not independently reported: %+v", oneShot)
	}
}
