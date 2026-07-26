// Package mcp implements an embedded Model Context Protocol server (JSON-RPC
// 2.0 over HTTP) so an AI assistant (Claude, Cursor, ...) can operate the
// control plane in natural language. It is mounted at /mcp by the API layer —
// deliberately NOT a sidecar, per the specification.
//
// The server exposes Tools (actions), Resources (live state), and Prompts
// (diagnostic templates). All actions are backed by real control-plane
// components (the supervisor gRPC client + the featurizer), and every
// AI-initiated call returns a structured result suitable for audit logging.
package mcp

import "encoding/json"

// MCP protocol version this server speaks.
const ProtocolVersion = "2024-11-05"

// Standard JSON-RPC 2.0 error codes.
const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternalError  = -32603
)

// rpcRequest is a JSON-RPC 2.0 request envelope.
type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// rpcError is a JSON-RPC 2.0 error object.
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// rpcResponse is a JSON-RPC 2.0 response envelope.
type rpcResponse struct {
	JSONRPC string    `json:"jsonrpc"`
	ID      any       `json:"id"`
	Result  any       `json:"result,omitempty"`
	Error   *rpcError `json:"error,omitempty"`
}

// Tool describes one callable tool for `tools/list`.
type Tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

// Resource describes one addressable live-state item for `resources/list`.
type Resource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description"`
	MimeType    string `json:"mimeType"`
}

// PromptArgument is one named argument a prompt template accepts.
type PromptArgument struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Required    bool   `json:"required"`
}

// Prompt describes one prompt template for `prompts/list`.
type Prompt struct {
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Arguments   []PromptArgument `json:"arguments"`
}

// CallResult is the content returned by `tools/call`.
type CallResult struct {
	Content []Content `json:"content"`
	IsError bool      `json:"isError"`
}

// Content is one piece of tool/prompt output (text is the only kind here).
type Content struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// TextResult builds a single-text CallResult.
func TextResult(text string) CallResult {
	return CallResult{Content: []Content{{Type: "text", Text: text}}}
}

// ErrorResult builds an error-flagged CallResult (the call executed but failed).
func ErrorResult(text string) CallResult {
	return CallResult{Content: []Content{{Type: "text", Text: text}}, IsError: true}
}
