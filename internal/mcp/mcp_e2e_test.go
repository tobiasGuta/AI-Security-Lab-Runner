package mcp_test

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/config"
	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/docker"
	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/lab"
	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/mcp"
)

type jsonRPCClient struct {
	in  *bufio.Reader
	out io.Writer
	id  int64
}

func newJSONRPCClient(in io.Reader, out io.Writer) *jsonRPCClient {
	return &jsonRPCClient{
		in:  bufio.NewReader(in),
		out: out,
	}
}

func (c *jsonRPCClient) Call(method string, params interface{}) (json.RawMessage, error) {
	c.id++
	req := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      c.id,
		"method":  method,
	}
	if params != nil {
		req["params"] = params
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	reqBytes = append(reqBytes, '\n')
	if _, err := c.out.Write(reqBytes); err != nil {
		return nil, err
	}

	line, err := c.in.ReadBytes('\n')
	if err != nil {
		return nil, err
	}

	var resp struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      int64           `json:"id"`
		Result  json.RawMessage `json:"result"`
		Error   *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}

	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, err
	}

	if resp.Error != nil {
		return nil, &http.ProtocolError{}
	}

	return resp.Result, nil
}

func (c *jsonRPCClient) CallTool(toolName string, args interface{}) (json.RawMessage, error) {
	argsBytes, err := json.Marshal(args)
	if err != nil {
		return nil, err
	}
	toolParams := map[string]interface{}{
		"name":      toolName,
		"arguments": json.RawMessage(argsBytes),
	}
	rawRes, err := c.Call("tools/call", toolParams)
	if err != nil {
		return nil, err
	}

	var callResult struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(rawRes, &callResult); err != nil {
		return nil, err
	}

	if callResult.IsError || len(callResult.Content) == 0 {
		return nil, err
	}

	return json.RawMessage(callResult.Content[0].Text), nil
}

func skipIfDockerUnavailable(t *testing.T, cliClient *docker.CLIClient) {
	ctx := context.Background()
	if err := cliClient.CheckDockerAvailable(ctx); err != nil {
		t.Skipf("Docker daemon unavailable: %v", err)
	}
	if err := cliClient.CheckComposeAvailable(ctx); err != nil {
		t.Skipf("Docker compose unavailable: %v", err)
	}
	if err := cliClient.CheckLinuxContainers(ctx); err != nil {
		t.Skipf("Linux containers check failed: %v", err)
	}
}

func TestMCPEndToEndContinuity(t *testing.T) {
	cliClient := docker.NewCLIClient()
	skipIfDockerUnavailable(t, cliClient)

	tempState, err := os.MkdirTemp("", "mcp_e2e_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempState)

	cfg := config.DefaultConfig()
	cfg.StateDir = tempState

	eng, err := lab.NewEngine(cfg, cliClient, nil)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	clientToServerR, clientToServerW := io.Pipe()
	serverToClientR, serverToClientW := io.Pipe()

	server := mcp.NewServer(eng, clientToServerR, serverToClientW)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = server.Serve(ctx)
	}()

	rpcClient := newJSONRPCClient(serverToClientR, clientToServerW)

	// Initialize MCP session
	_, err = rpcClient.Call("initialize", nil)
	if err != nil {
		t.Fatalf("MCP initialize failed: %v", err)
	}

	// 1. Call sandbox_start
	startRaw, err := rpcClient.CallTool("sandbox_start", map[string]interface{}{"ttl_minutes": 15})
	if err != nil {
		t.Fatalf("sandbox_start failed: %v", err)
	}
	var startRes lab.StartResult
	if err := json.Unmarshal(startRaw, &startRes); err != nil {
		t.Fatalf("Unmarshal sandbox_start result failed: %v", err)
	}
	sessID := startRes.SessionID
	if sessID == "" {
		t.Fatal("sandbox_start returned empty session_id")
	}

	defer func() {
		_, _ = rpcClient.CallTool("sandbox_stop", map[string]interface{}{"session_id": sessID})
	}()

	// 2 & 3 & 4. Call sandbox_exec: python3 -c "print('STDOUT_OK')"
	execRaw, err := rpcClient.CallTool("sandbox_exec", map[string]interface{}{
		"session_id": sessID,
		"command":    `python3 -c "print('STDOUT_OK')"`,
	})
	if err != nil {
		t.Fatalf("sandbox_exec stdout test failed: %v", err)
	}
	var execRes lab.ExecResult
	if err := json.Unmarshal(execRaw, &execRes); err != nil {
		t.Fatalf("Unmarshal sandbox_exec result failed: %v", err)
	}

	if execRes.ExitCode != 0 {
		t.Errorf("Expected exit_code 0, got %d", execRes.ExitCode)
	}
	if execRes.Stdout != "STDOUT_OK\n" {
		t.Errorf("Expected stdout 'STDOUT_OK\\n', got %q", execRes.Stdout)
	}
	if execRes.Stderr != "" {
		t.Errorf("Expected empty stderr, got %q", execRes.Stderr)
	}
	if execRes.SessionID != sessID {
		t.Errorf("Expected session_id %s, got %s", sessID, execRes.SessionID)
	}

	// 5. Call sandbox_exec: python3 write file
	execWriteRaw, err := rpcClient.CallTool("sandbox_exec", map[string]interface{}{
		"session_id": sessID,
		"command":    `python3 -c "open('/scratch/from_exec.txt','w').write('EXEC_FILE_OK')"`,
	})
	if err != nil {
		t.Fatalf("sandbox_exec file write failed: %v", err)
	}
	var execWriteRes lab.ExecResult
	_ = json.Unmarshal(execWriteRaw, &execWriteRes)
	if execWriteRes.ExitCode != 0 {
		t.Fatalf("sandbox_exec file write returned exit_code %d", execWriteRes.ExitCode)
	}

	// 6 & 7. Call sandbox_read_file with same session_id
	readRaw, err := rpcClient.CallTool("sandbox_read_file", map[string]interface{}{
		"session_id": sessID,
		"path":       "/scratch/from_exec.txt",
	})
	if err != nil {
		t.Fatalf("sandbox_read_file failed: %v", err)
	}
	var readRes lab.ReadResult
	if err := json.Unmarshal(readRaw, &readRes); err != nil {
		t.Fatalf("Unmarshal sandbox_read_file result failed: %v", err)
	}
	if readRes.Content != "EXEC_FILE_OK" {
		t.Errorf("Expected content 'EXEC_FILE_OK', got %q", readRes.Content)
	}

	// 8. Call sandbox_write_file
	writeRaw, err := rpcClient.CallTool("sandbox_write_file", map[string]interface{}{
		"session_id": sessID,
		"path":       "/scratch/from_write_tool.txt",
		"content":    "WRITE_TOOL_OK",
		"overwrite":  true,
	})
	if err != nil {
		t.Fatalf("sandbox_write_file failed: %v", err)
	}
	var writeRes lab.WriteResult
	if err := json.Unmarshal(writeRaw, &writeRes); err != nil {
		t.Fatalf("Unmarshal sandbox_write_file result failed: %v", err)
	}

	// 9 & 10. Call sandbox_exec: cat /scratch/from_write_tool.txt
	catRaw, err := rpcClient.CallTool("sandbox_exec", map[string]interface{}{
		"session_id": sessID,
		"command":    "cat /scratch/from_write_tool.txt",
	})
	if err != nil {
		t.Fatalf("sandbox_exec cat failed: %v", err)
	}
	var catRes lab.ExecResult
	if err := json.Unmarshal(catRaw, &catRes); err != nil {
		t.Fatalf("Unmarshal cat result failed: %v", err)
	}
	if catRes.Stdout != "WRITE_TOOL_OK" {
		t.Errorf("Expected cat stdout 'WRITE_TOOL_OK', got %q", catRes.Stdout)
	}

	// 11. Call sandbox_status
	statusRaw, err := rpcClient.CallTool("sandbox_status", map[string]interface{}{
		"session_id": sessID,
	})
	if err != nil {
		t.Fatalf("sandbox_status failed: %v", err)
	}
	var statusRes lab.PublicStatus
	if err := json.Unmarshal(statusRaw, &statusRes); err != nil {
		t.Fatalf("Unmarshal sandbox_status result failed: %v", err)
	}
	if statusRes.SessionID != sessID {
		t.Errorf("Expected status session_id %s, got %s", sessID, statusRes.SessionID)
	}
	if statusRes.Status != "ready" {
		t.Errorf("Expected status 'ready', got %s", statusRes.Status)
	}

	// 12. Call sandbox_stop
	stopRaw, err := rpcClient.CallTool("sandbox_stop", map[string]interface{}{
		"session_id": sessID,
	})
	if err != nil {
		t.Fatalf("sandbox_stop failed: %v", err)
	}
	var stopRes lab.StopResult
	if err := json.Unmarshal(stopRaw, &stopRes); err != nil {
		t.Fatalf("Unmarshal sandbox_stop result failed: %v", err)
	}
	if stopRes.Status != "stopped" {
		t.Errorf("Expected stop status 'stopped', got %s", stopRes.Status)
	}

	// 13. Confirm runner, network, volume and session state are removed
	time.Sleep(500 * time.Millisecond)
	managed, err := cliClient.ListManagedResources(ctx)
	if err != nil {
		t.Fatalf("ListManagedResources failed: %v", err)
	}
	for _, res := range managed {
		if strings.Contains(res, sessID) {
			t.Errorf("Resource for session %s still present in Docker: %s", sessID, res)
		}
	}
}
