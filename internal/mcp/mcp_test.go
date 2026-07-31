package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (n int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func (s *safeBuffer) Bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.buf.Bytes()
	cp := make([]byte, len(b))
	copy(cp, b)
	return cp
}

func TestMCPServerSandboxToolsList(t *testing.T) {
	reqJSON := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n"
	inBuf := bytes.NewBufferString(reqJSON)
	outBuf := &safeBuffer{}

	server := NewServer(nil, inBuf, outBuf)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = server.Serve(ctx)
	}()

	// Wait for response
	time.Sleep(100 * time.Millisecond)
	cancel()

	outStr := outBuf.String()
	if !strings.Contains(outStr, `"jsonrpc":"2.0"`) || !strings.Contains(outStr, `"sandbox_run"`) {
		t.Fatalf("expected sandbox_run in tools list JSON-RPC output, got: %s", outStr)
	}

	if strings.Contains(outStr, "lab_list_projects") || strings.Contains(outStr, "lab_start") {
		t.Fatalf("obsolete lab_* tools found in tools list: %s", outStr)
	}

	var resp JSONRPCResponse
	if err := json.Unmarshal(outBuf.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal server response: %v", err)
	}

	if resp.Error != nil {
		t.Fatalf("server returned error: %v", resp.Error)
	}
}
