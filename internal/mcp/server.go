package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/lab"
	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/transcript"
)

type Server struct {
	mu              sync.Mutex
	engine          *lab.Engine
	in              io.Reader
	out             io.Writer
	transcriptStore *transcript.Store
}

func NewServer(engine *lab.Engine, in io.Reader, out io.Writer) *Server {
	return NewServerWithTranscript(engine, in, out, nil)
}

func NewServerWithTranscript(engine *lab.Engine, in io.Reader, out io.Writer, transcriptStore *transcript.Store) *Server {
	if in == nil {
		in = os.Stdin
	}
	if out == nil {
		out = os.Stdout
	}
	return &Server{
		engine:          engine,
		in:              in,
		out:             out,
		transcriptStore: transcriptStore,
	}
}

// Serve handles incoming JSON-RPC stdio frames.
// Invariant 19: stdout contains no non-protocol output.
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
				"name":    "ai-security-sandbox",
				"version": "2.0.0",
			},
		}
		s.sendResult(req.ID, result)

	case "notifications/initialized":

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

	operationID := transcript.NewEventID()
	sessionID, inputEvent := transcriptInputEvent(params.Name, params.Arguments)
	if s.transcriptStore != nil && shouldRecordTranscript(params.Name) && sessionID != "" {
		inputEvent.EventID = transcript.NewEventID()
		inputEvent.OperationID = operationID
		inputEvent.SessionID = sessionID
		inputEvent.Interface = "mcp"
		inputEvent.Tool = params.Name
		inputEvent.Phase = "started"
		_ = s.transcriptStore.Append(inputEvent)
	}

	startedAt := time.Now()
	toolResult, err := s.executeTool(ctx, params.Name, params.Arguments)
	durationMS := time.Since(startedAt).Milliseconds()

	if s.transcriptStore != nil && shouldRecordTranscript(params.Name) {
		finishSessionID := sessionID
		if finishSessionID == "" {
			finishSessionID = sessionIDFromResult(toolResult)
		}
		if finishSessionID != "" {
			finishEvent := transcriptResultEvent(params.Name, params.Arguments, toolResult, err, durationMS)
			finishEvent.EventID = transcript.NewEventID()
			finishEvent.OperationID = operationID
			finishEvent.SessionID = finishSessionID
			finishEvent.Interface = "mcp"
			finishEvent.Tool = params.Name
			if err != nil {
				finishEvent.Phase = "failed"
			} else {
				finishEvent.Phase = "completed"
			}
			_ = s.transcriptStore.Append(finishEvent)
		}
	}

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
	case "sandbox_run":
		var p struct {
			Command        string            `json:"command"`
			CWD            string            `json:"cwd"`
			TimeoutSeconds int               `json:"timeout_seconds"`
			Environment    map[string]string `json:"environment"`
		}
		if err := json.Unmarshal(args, &p); err != nil {
			return nil, err
		}
		return s.engine.Run(ctx, p.Command, p.CWD, p.TimeoutSeconds, p.Environment)

	case "sandbox_start":
		var p struct {
			OutboundNetwork *bool `json:"outbound_network"`
			HostAccess      *bool `json:"host_access"`
			TTLMinutes      int   `json:"ttl_minutes"`
		}
		_ = json.Unmarshal(args, &p)
		return s.engine.StartSession(ctx, p.OutboundNetwork, p.HostAccess, p.TTLMinutes)

	case "sandbox_exec":
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

	case "sandbox_http_request":
		var opts lab.HTTPRequestOptions
		if err := json.Unmarshal(args, &opts); err != nil {
			return nil, err
		}
		return s.engine.HTTPRequest(ctx, opts)

	case "sandbox_write_file":
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
		return s.engine.WriteFile(ctx, p.SessionID, p.Path, p.Content, p.Encoding, p.Overwrite)

	case "sandbox_read_file":
		var p struct {
			SessionID      string `json:"session_id"`
			Path           string `json:"path"`
			Offset         int64  `json:"offset"`
			MaximumBytes   int64  `json:"maximum_bytes"`
			BinaryEncoding string `json:"binary_encoding"`
		}
		if err := json.Unmarshal(args, &p); err != nil {
			return nil, err
		}
		return s.engine.ReadFile(ctx, p.SessionID, p.Path, p.Offset, p.MaximumBytes, p.BinaryEncoding)

	case "sandbox_export_file":
		var p struct {
			SessionID       string `json:"session_id"`
			ScratchPath     string `json:"scratch_path"`
			DestinationName string `json:"destination_name"`
		}
		_ = json.Unmarshal(args, &p)
		return s.engine.ExportFile(ctx, p.SessionID, p.ScratchPath, p.DestinationName)

	case "sandbox_status":
		var p struct {
			SessionID string `json:"session_id"`
		}
		_ = json.Unmarshal(args, &p)
		return s.engine.Status(p.SessionID)

	case "sandbox_stop":
		var p struct {
			SessionID       string `json:"session_id"`
			PreserveScratch bool   `json:"preserve_scratch"`
		}
		if err := json.Unmarshal(args, &p); err != nil {
			return nil, err
		}
		return s.engine.StopSession(ctx, p.SessionID)

	case "sandbox_reset":
		var p struct {
			SessionID string `json:"session_id"`
		}
		if err := json.Unmarshal(args, &p); err != nil {
			return nil, err
		}
		return s.engine.ResetSession(ctx, p.SessionID)

	case "sandbox_get_logs":
		var p struct {
			SessionID    string `json:"session_id"`
			AfterEventID string `json:"after_event_id"`
			Limit        int    `json:"limit"`
			IncludeOutput bool   `json:"include_output"`
		}
		if err := json.Unmarshal(args, &p); err != nil {
			return nil, err
		}
		if s.transcriptStore == nil {
			return map[string]interface{}{
				"session_id":  p.SessionID,
				"events":      []transcript.Event{},
				"next_cursor": p.AfterEventID,
			}, nil
		}
		if p.Limit <= 0 {
			p.Limit = 50
		}
		if p.Limit > 200 {
			p.Limit = 200
		}
		events, err := s.transcriptStore.ReadSession(p.SessionID, p.AfterEventID, p.Limit)
		if err != nil {
			return nil, err
		}
		if !p.IncludeOutput {
			events = transcript.StripOutput(events)
		}
		nextCursor := p.AfterEventID
		if len(events) > 0 {
			nextCursor = events[len(events)-1].EventID
		}
		return map[string]interface{}{
			"session_id":  p.SessionID,
			"events":      events,
			"next_cursor": nextCursor,
		}, nil

	case "sandbox_get_audit_summary":
		var p struct {
			SessionID string `json:"session_id"`
			Limit     int    `json:"limit"`
		}
		if err := json.Unmarshal(args, &p); err != nil {
			return nil, err
		}
		return s.engine.GetAuditSummary(p.SessionID, p.Limit)

	default:
		return nil, fmt.Errorf("unknown tool name '%s'", name)
	}
}

func shouldRecordTranscript(tool string) bool {
	switch tool {
	case "sandbox_get_logs", "sandbox_get_audit_summary", "sandbox_status":
		return false
	default:
		return true
	}
}

func transcriptInputEvent(tool string, args json.RawMessage) (string, transcript.Event) {
	var raw map[string]interface{}
	_ = json.Unmarshal(args, &raw)

	event := transcript.Event{}
	sessionID, _ := raw["session_id"].(string)
	if command, ok := raw["command"].(string); ok {
		event.Command = command
	}
	if method, ok := raw["method"].(string); ok {
		event.Method = method
	}
	if rawURL, ok := raw["url"].(string); ok {
		event.URL = rawURL
	}
	if p, ok := raw["path"].(string); ok {
		event.Path = p
	} else if p, ok := raw["scratch_path"].(string); ok {
		event.Path = p
	}

	event.Details = map[string]interface{}{}
	switch tool {
	case "sandbox_write_file":
		if content, ok := raw["content"].(string); ok {
			event.Details["content_bytes"] = len(content)
		}
		if overwrite, ok := raw["overwrite"].(bool); ok {
			event.Details["overwrite"] = overwrite
		}
	case "sandbox_start":
		if v, ok := raw["outbound_network"]; ok {
			event.Details["outbound_network"] = v
		}
		if v, ok := raw["host_access"]; ok {
			event.Details["host_access"] = v
		}
		if v, ok := raw["ttl_minutes"]; ok {
			event.Details["ttl_minutes"] = v
		}
	case "sandbox_export_file":
		if v, ok := raw["destination_name"].(string); ok {
			event.Details["destination_name"] = v
		}
	}
	if len(event.Details) == 0 {
		event.Details = nil
	}

	return sessionID, event
}

func transcriptResultEvent(tool string, args json.RawMessage, result interface{}, toolErr error, fallbackDurationMS int64) transcript.Event {
	_, event := transcriptInputEvent(tool, args)
	event.DurationMS = fallbackDurationMS
	if toolErr != nil {
		event.Error = toolErr.Error()
	}

	var raw map[string]interface{}
	if result != nil {
		if data, err := json.Marshal(result); err == nil {
			_ = json.Unmarshal(data, &raw)
		}
	}
	if raw == nil {
		return event
	}

	if duration, ok := numberAsInt(raw["duration_ms"]); ok {
		event.DurationMS = int64(duration)
	}
	if exit, ok := numberAsInt(raw["exit_code"]); ok {
		event.ExitCode = &exit
	}
	if status, ok := numberAsInt(raw["status_code"]); ok {
		event.HTTPStatus = &status
	}
	if stdout, ok := raw["stdout"].(string); ok {
		event.Stdout = stdout
	}
	if stderr, ok := raw["stderr"].(string); ok {
		event.Stderr = stderr
	}
	if timedOut, ok := raw["timed_out"].(bool); ok {
		event.TimedOut = timedOut
	}
	if truncated, ok := raw["truncated"].(bool); ok {
		event.OutputTruncated = truncated
	}
	if truncated, ok := raw["stdout_truncated"].(bool); ok && truncated {
		event.OutputTruncated = true
	}
	if truncated, ok := raw["stderr_truncated"].(bool); ok && truncated {
		event.OutputTruncated = true
	}

	if event.Details == nil {
		event.Details = map[string]interface{}{}
	}
	for _, key := range []string{"execution_mode", "status", "normalized_path", "bytes_written", "bytes", "source_path"} {
		if value, ok := raw[key]; ok {
			event.Details[key] = value
		}
	}
	if resultSessionID, ok := raw["session_id"].(string); ok {
		inputSessionID, _ := transcriptInputEvent(tool, args)
		if inputSessionID != "" && resultSessionID != inputSessionID {
			event.Details["new_session_id"] = resultSessionID
		}
	}
	if len(event.Details) == 0 {
		event.Details = nil
	}

	return event
}

func sessionIDFromResult(result interface{}) string {
	if result == nil {
		return ""
	}
	data, err := json.Marshal(result)
	if err != nil {
		return ""
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return ""
	}
	sessionID, _ := raw["session_id"].(string)
	return sessionID
}

func numberAsInt(value interface{}) (int, bool) {
	switch v := value.(type) {
	case float64:
		return int(v), true
	case int:
		return v, true
	case int64:
		return int(v), true
	default:
		return 0, false
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
