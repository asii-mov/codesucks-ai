package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Client represents an MCP client
type Client struct {
	serverURL   string
	httpClient  *http.Client
	timeout     time.Duration
	mu          sync.RWMutex
	pendingReqs map[string]chan *Response
	tools       map[string]Tool
}

// ClientConfig represents MCP client configuration
type ClientConfig struct {
	ServerURL string
	Timeout   time.Duration
	Transport http.RoundTripper
}

// NewClient creates a new MCP client
func NewClient(config ClientConfig) (*Client, error) {
	if config.ServerURL == "" {
		return nil, fmt.Errorf("server URL is required")
	}

	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}

	httpClient := &http.Client{
		Timeout:   config.Timeout,
		Transport: config.Transport,
	}

	client := &Client{
		serverURL:   config.ServerURL,
		httpClient:  httpClient,
		timeout:     config.Timeout,
		pendingReqs: make(map[string]chan *Response),
		tools:       make(map[string]Tool),
	}

	// Initialize connection and discover tools
	if err := client.initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize MCP client: %w", err)
	}

	return client, nil
}

// initialize connects to the server and discovers available tools
func (c *Client) initialize() error {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	// Send initialization request
	resp, err := c.Request(ctx, "initialize", map[string]interface{}{
		"protocol_version": ProtocolVersion,
		"client_info": map[string]interface{}{
			"name":    "codesucks-ai",
			"version": "1.0.0",
		},
	})

	if err != nil {
		return fmt.Errorf("initialization failed: %w", err)
	}

	// Parse server capabilities
	if resp.Result != nil {
		if serverInfo, ok := resp.Result.(map[string]interface{}); ok {
			// Store server capabilities
			if tools, ok := serverInfo["tools"].([]interface{}); ok {
				for _, tool := range tools {
					if t, ok := tool.(map[string]interface{}); ok {
						c.registerTool(t)
					}
				}
			}
		}
	}

	return nil
}

// registerTool registers a tool from server response
func (c *Client) registerTool(toolData map[string]interface{}) {
	name, ok := toolData["name"].(string)
	if !ok || name == "" {
		return
	}

	desc, _ := toolData["description"].(string)
	params, _ := toolData["parameters"].(map[string]interface{})

	c.mu.Lock()
	c.tools[name] = Tool{
		Name:        name,
		Description: desc,
		Parameters:  params,
	}
	c.mu.Unlock()
}

// Request sends a request to the MCP server
func (c *Client) Request(ctx context.Context, method string, params map[string]interface{}) (*Response, error) {
	requestID := uuid.New().String()

	req := NewRequest(requestID, method, params)

	// Marshal request
	reqData, err := Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.serverURL, bytes.NewReader(reqData))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	// Send request
	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer httpResp.Body.Close()

	// Read response
	respData, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Parse response
	msg, err := ParseMessage(respData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	resp, ok := msg.(*Response)
	if !ok {
		return nil, fmt.Errorf("unexpected response type: %T", msg)
	}

	// Check for errors
	if resp.Error != nil {
		return nil, fmt.Errorf("server error: %s (code: %d)", resp.Error.Message, resp.Error.Code)
	}

	return resp, nil
}

// CallTool calls a specific tool on the MCP server
func (c *Client) CallTool(ctx context.Context, name string, arguments map[string]interface{}) (*ToolResult, error) {
	// Check if tool exists
	c.mu.RLock()
	_, exists := c.tools[name]
	c.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("tool %s not found", name)
	}

	// Create tool call
	resp, err := c.Request(ctx, "tools/call", map[string]interface{}{
		"name":      name,
		"arguments": arguments,
	})

	if err != nil {
		return nil, err
	}

	// Parse tool result
	if resp.Result == nil {
		return nil, fmt.Errorf("empty tool result")
	}

	resultData, err := json.Marshal(resp.Result)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal tool result: %w", err)
	}

	var result ToolResult
	if err := json.Unmarshal(resultData, &result); err != nil {
		// If unmarshaling fails, wrap the result
		result = ToolResult{
			Content: resp.Result,
		}
	}

	return &result, nil
}

// ListTools returns available tools
func (c *Client) ListTools() []Tool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	tools := make([]Tool, 0, len(c.tools))
	for _, tool := range c.tools {
		tools = append(tools, tool)
	}

	return tools
}

// GetTool returns a specific tool by name
func (c *Client) GetTool(name string) (Tool, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	tool, exists := c.tools[name]
	return tool, exists
}

// Close closes the MCP client connection
func (c *Client) Close() error {
	// Send disconnect notification
	notif := NewNotification("disconnect", nil)
	notifData, err := Marshal(notif)
	if err != nil {
		// Log error but don't fail close
		return nil
	}

	req, err := http.NewRequest("POST", c.serverURL, bytes.NewReader(notifData))
	if err != nil {
		// Log error but don't fail close
		return nil
	}
	req.Header.Set("Content-Type", "application/json")

	// Best effort disconnect - ignore errors as server may be down
	_, _ = c.httpClient.Do(req)

	return nil
}

// Ping checks if the server is responsive
func (c *Client) Ping(ctx context.Context) error {
	resp, err := c.Request(ctx, "ping", nil)
	if err != nil {
		return err
	}

	if resp.Error != nil {
		return fmt.Errorf("ping failed: %s", resp.Error.Message)
	}

	return nil
}
