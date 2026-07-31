package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestMCPServerToolsList(t *testing.T) {
	reqJSON := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n"
	inBuf := bytes.NewBufferString(reqJSON)
	outBuf := &bytes.Buffer{}

	server := NewServer(nil, inBuf, outBuf)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = server.Serve(ctx)
	}()

	// Give serve loop time to process single line
	for outBuf.Len() == 0 {
	}
	cancel()

	outStr := outBuf.String()
	if !strings.Contains(outStr, `"jsonrpc":"2.0"`) || !strings.Contains(outStr, `"lab_list_projects"`) {
		t.Fatalf("expected tools list in JSON-RPC output, got: %s", outStr)
	}

	var resp JSONRPCResponse
	if err := json.Unmarshal(outBuf.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal server response: %v", err)
	}

	if resp.Error != nil {
		t.Fatalf("server returned error: %v", resp.Error)
	}
}
