package mcp

import (
	"encoding/json"
	"fmt"
)

// MCP Protocol Version
const ProtocolVersion = "1.0.0"

// MessageType represents the type of MCP message
type MessageType string

const (
	MessageTypeRequest  MessageType = "request"
	MessageTypeResponse MessageType = "response"
	MessageTypeError    MessageType = "error"
	MessageTypeNotify   MessageType = "notify"
)

// Request represents an MCP request message
type Request struct {
	ID      string                 `json:"id"`
	Type    MessageType            `json:"type"`
	Method  string                 `json:"method"`
	Params  map[string]interface{} `json:"params,omitempty"`
	Version string                 `json:"version"`
}

// Response represents an MCP response message
type Response struct {
	ID      string                 `json:"id"`
	Type    MessageType            `json:"type"`
	Result  interface{}            `json:"result,omitempty"`
	Error   *ErrorResponse         `json:"error,omitempty"`
	Version string                 `json:"version"`
}

// ErrorResponse represents an error in MCP protocol
type ErrorResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// Notification represents an MCP notification message
type Notification struct {
	Type    MessageType            `json:"type"`
	Method  string                 `json:"method"`
	Params  map[string]interface{} `json:"params,omitempty"`
	Version string                 `json:"version"`
}

// Tool represents an MCP tool definition
type Tool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Parameters  map[string]interface{} `json:"parameters,omitempty"`
}

// ToolCall represents a call to an MCP tool
type ToolCall struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

// ToolResult represents the result of a tool call
type ToolResult struct {
	ToolCallID string      `json:"tool_call_id"`
	Content    interface{} `json:"content"`
	IsError    bool        `json:"is_error,omitempty"`
}

// NewRequest creates a new MCP request
func NewRequest(id, method string, params map[string]interface{}) *Request {
	return &Request{
		ID:      id,
		Type:    MessageTypeRequest,
		Method:  method,
		Params:  params,
		Version: ProtocolVersion,
	}
}

// NewResponse creates a new MCP response
func NewResponse(id string, result interface{}) *Response {
	return &Response{
		ID:      id,
		Type:    MessageTypeResponse,
		Result:  result,
		Version: ProtocolVersion,
	}
}

// NewErrorResponse creates a new MCP error response
func NewErrorResponse(id string, code int, message string, data interface{}) *Response {
	return &Response{
		ID:   id,
		Type: MessageTypeError,
		Error: &ErrorResponse{
			Code:    code,
			Message: message,
			Data:    data,
		},
		Version: ProtocolVersion,
	}
}

// NewNotification creates a new MCP notification
func NewNotification(method string, params map[string]interface{}) *Notification {
	return &Notification{
		Type:    MessageTypeNotify,
		Method:  method,
		Params:  params,
		Version: ProtocolVersion,
	}
}

// Marshal serializes an MCP message to JSON
func Marshal(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

// Unmarshal deserializes JSON to an MCP message
func Unmarshal(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}

// ParseMessage parses a raw message and returns the appropriate type
func ParseMessage(data []byte) (interface{}, error) {
	var base struct {
		Type   MessageType `json:"type"`
		Method string      `json:"method,omitempty"`
		ID     string      `json:"id,omitempty"`
	}
	
	if err := json.Unmarshal(data, &base); err != nil {
		return nil, fmt.Errorf("failed to parse message: %w", err)
	}
	
	switch base.Type {
	case MessageTypeRequest:
		var req Request
		if err := json.Unmarshal(data, &req); err != nil {
			return nil, fmt.Errorf("failed to parse request: %w", err)
		}
		return &req, nil
		
	case MessageTypeResponse, MessageTypeError:
		var resp Response
		if err := json.Unmarshal(data, &resp); err != nil {
			return nil, fmt.Errorf("failed to parse response: %w", err)
		}
		return &resp, nil
		
	case MessageTypeNotify:
		var notif Notification
		if err := json.Unmarshal(data, &notif); err != nil {
			return nil, fmt.Errorf("failed to parse notification: %w", err)
		}
		return &notif, nil
		
	default:
		return nil, fmt.Errorf("unknown message type: %s", base.Type)
	}
}