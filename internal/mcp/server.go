package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/ai-security-lab-runner/lab-runner/internal/lab"
)

type Server struct {
	mu     sync.Mutex
	engine *lab.Engine
	in     io.Reader
	out    io.Writer
}

func NewServer(engine *lab.Engine, in io.Reader, out io.Writer) *Server {
	if in == nil {
		in = os.Stdin
	}
	if out == nil {
		out = os.Stdout
	}
	return &Server{
		engine: engine,
		in:     in,
		out:    out,
	}
}

// Invariant 19: MCP stdout contains no non-protocol output.
func (s *Server) Serve(ctx context.Context) error {
	reader := bufio.NewReader(s.in)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line, err := reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("error reading stdio: %w", err)
		}

		if len(line) == 0 || line[0] == '\n' || line[0] == '\r' {
			continue
		}

		var req JSONRPCRequest
		if err := json.Unmarshal(line, &req); err != nil {
			s.sendError(nil, -32700, "Parse error", err.Error())
			continue
		}

		s.handleRequest(ctx, req)
	}
}

func (s *Server) handleRequest(ctx context.Context, req JSONRPCRequest) {
	switch req.Method {
	case "initialize":
		result := map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities": map[string]interface{}{
				"tools": map[string]interface{}{},
			},
			"serverInfo": map[string]interface{}{
				"name":    "ai-security-lab-runner",
				"version": "1.0.0",
			},
		}
		s.sendResult(req.ID, result)

	case "notifications/initialized":
		// No response required for notification

	case "ping":
		s.sendResult(req.ID, map[string]interface{}{})

	case "tools/list":
		s.sendResult(req.ID, map[string]interface{}{
			"tools": GetDefinedTools(),
		})

	case "tools/call":
		s.handleToolCall(ctx, req)

	default:
		if req.ID != nil {
			s.sendError(req.ID, -32601, "Method not found", fmt.Sprintf("Method '%s' is not supported", req.Method))
		}
	}
}

func (s *Server) handleToolCall(ctx context.Context, req JSONRPCRequest) {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}

	if err := json.Unmarshal(req.Params, &params); err != nil {
		s.sendError(req.ID, -32602, "Invalid params", err.Error())
		return
	}

	toolResult, err := s.executeTool(ctx, params.Name, params.Arguments)
	if err != nil {
		s.sendResult(req.ID, CallToolResult{
			Content: []ToolContent{
				{Type: "text", Text: fmt.Sprintf("Tool Error: %v", err)},
			},
			IsError: true,
		})
		return
	}

	jsonBytes, _ := json.MarshalIndent(toolResult, "", "  ")
	s.sendResult(req.ID, CallToolResult{
		Content: []ToolContent{
			{Type: "text", Text: string(jsonBytes)},
		},
		IsError: false,
	})
}

func (s *Server) executeTool(ctx context.Context, name string, args json.RawMessage) (interface{}, error) {
	switch name {
	case "lab_list_projects":
		var p struct {
			IncludeInvalid bool `json:"include_invalid"`
		}
		_ = json.Unmarshal(args, &p)
		projects, err := s.engine.ListProjects()
		if err != nil {
			return nil, err
		}
		if !p.IncludeInvalid {
			var filtered []lab.ProjectInfo
			for _, proj := range projects {
				if proj.IsValid {
					filtered = append(filtered, proj)
				}
			}
			return filtered, nil
		}
		return projects, nil

	case "lab_start":
		var p struct {
			Project string `json:"project"`
			Rebuild bool   `json:"rebuild"`
		}
		if err := json.Unmarshal(args, &p); err != nil {
			return nil, err
		}
		return s.engine.StartSession(ctx, p.Project, p.Rebuild)

	case "lab_exec":
		var p struct {
			SessionID      string            `json:"session_id"`
			Command        string            `json:"command"`
			CWD            string            `json:"cwd"`
			TimeoutSeconds int               `json:"timeout_seconds"`
			Environment    map[string]string `json:"environment"`
		}
		if err := json.Unmarshal(args, &p); err != nil {
			return nil, err
		}
		return s.engine.Exec(ctx, p.SessionID, p.Command, p.CWD, p.TimeoutSeconds, p.Environment)

	case "lab_read_file":
		var p struct {
			SessionID    string `json:"session_id"`
			Path         string `json:"path"`
			Offset       int64  `json:"offset"`
			MaximumBytes int64  `json:"maximum_bytes"`
		}
		if err := json.Unmarshal(args, &p); err != nil {
			return nil, err
		}
		return s.engine.ReadFile(ctx, p.SessionID, p.Path, p.Offset, p.MaximumBytes)

	case "lab_write_scratch":
		var p struct {
			SessionID string `json:"session_id"`
			Path      string `json:"path"`
			Content   string `json:"content"`
			Encoding  string `json:"encoding"`
			Overwrite bool   `json:"overwrite"`
		}
		if err := json.Unmarshal(args, &p); err != nil {
			return nil, err
		}
		return s.engine.WriteScratch(ctx, p.SessionID, p.Path, p.Content, p.Encoding, p.Overwrite)

	case "lab_status":
		var p struct {
			SessionID string `json:"session_id"`
		}
		_ = json.Unmarshal(args, &p)
		if p.SessionID != "" {
			return s.engine.GetSessionStatus(p.SessionID)
		}
		return s.engine.ListSessions(), nil

	case "lab_export_file":
		var p struct {
			SessionID       string `json:"session_id"`
			Path            string `json:"path"`
			DestinationName string `json:"destination_name"`
		}
		if err := json.Unmarshal(args, &p); err != nil {
			return nil, err
		}
		return s.engine.ExportFile(ctx, p.SessionID, p.Path, p.DestinationName)

	case "lab_reset":
		var p struct {
			SessionID string `json:"session_id"`
			Rebuild   bool   `json:"rebuild"`
		}
		if err := json.Unmarshal(args, &p); err != nil {
			return nil, err
		}
		return s.engine.ResetSession(ctx, p.SessionID, p.Rebuild)

	case "lab_stop":
		var p struct {
			SessionID       string `json:"session_id"`
			PreserveScratch bool   `json:"preserve_scratch"`
		}
		if err := json.Unmarshal(args, &p); err != nil {
			return nil, err
		}
		err := s.engine.StopSession(ctx, p.SessionID)
		if err != nil {
			return nil, err
		}
		return map[string]string{"status": "stopped", "session_id": p.SessionID}, nil

	case "lab_get_audit_summary":
		var p struct {
			SessionID string `json:"session_id"`
			Limit     int    `json:"limit"`
		}
		if err := json.Unmarshal(args, &p); err != nil {
			return nil, err
		}
		return map[string]interface{}{
			"session_id": p.SessionID,
			"status":     "audit_summary_available",
		}, nil

	default:
		return nil, fmt.Errorf("unknown tool name '%s'", name)
	}
}

func (s *Server) sendResult(id interface{}, result interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()

	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}

	data, _ := json.Marshal(resp)
	data = append(data, '\n')
	_, _ = s.out.Write(data)
}

func (s *Server) sendError(id interface{}, code int, message string, details string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &JSONRPCError{
			Code:    code,
			Message: message,
			Data:    details,
		},
	}

	data, _ := json.Marshal(resp)
	data = append(data, '\n')
	_, _ = s.out.Write(data)
}
