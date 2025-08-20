package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClient(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Mock initialization response
		response := Response{
			ID:      "init-1",
			Type:    MessageTypeResponse,
			Version: ProtocolVersion,
			Result: map[string]interface{}{
				"protocol_version": ProtocolVersion,
				"server_info": map[string]interface{}{
					"name":    "test-server",
					"version": "1.0.0",
				},
				"tools": []interface{}{
					map[string]interface{}{
						"name":        "test_tool",
						"description": "A test tool",
						"parameters": map[string]interface{}{
							"param1": "string",
						},
					},
				},
			},
		}

		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	tests := []struct {
		name        string
		config      ClientConfig
		expectError bool
	}{
		{
			name: "creates client with valid config",
			config: ClientConfig{
				ServerURL: server.URL,
				Timeout:   5 * time.Second,
			},
			expectError: false,
		},
		{
			name: "fails with empty server URL",
			config: ClientConfig{
				ServerURL: "",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.config)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, client)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)

				// Verify tools were registered
				tools := client.ListTools()
				assert.Len(t, tools, 1)
				assert.Equal(t, "test_tool", tools[0].Name)
			}
		})
	}
}

func TestRequest(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req Request
		_ = json.NewDecoder(r.Body).Decode(&req)

		// Echo back request method in response
		response := Response{
			ID:      req.ID,
			Type:    MessageTypeResponse,
			Version: ProtocolVersion,
			Result: map[string]interface{}{
				"method": req.Method,
				"params": req.Params,
			},
		}

		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Create client without initialization
	client := &Client{
		serverURL:   server.URL,
		httpClient:  &http.Client{Timeout: 5 * time.Second},
		timeout:     5 * time.Second,
		pendingReqs: make(map[string]chan *Response),
		tools:       make(map[string]Tool),
	}

	ctx := context.Background()
	resp, err := client.Request(ctx, "test_method", map[string]interface{}{
		"key": "value",
	})

	require.NoError(t, err)
	require.NotNil(t, resp)

	result, ok := resp.Result.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "test_method", result["method"])
}

func TestCallTool(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req Request
		_ = json.NewDecoder(r.Body).Decode(&req)

		// Mock tool call response
		response := Response{
			ID:      req.ID,
			Type:    MessageTypeResponse,
			Version: ProtocolVersion,
			Result: map[string]interface{}{
				"content": "Tool executed successfully",
			},
		}

		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Create client with a registered tool
	client := &Client{
		serverURL:   server.URL,
		httpClient:  &http.Client{Timeout: 5 * time.Second},
		timeout:     5 * time.Second,
		pendingReqs: make(map[string]chan *Response),
		tools: map[string]Tool{
			"test_tool": {
				Name:        "test_tool",
				Description: "Test tool",
			},
		},
	}

	ctx := context.Background()

	// Test successful tool call
	result, err := client.CallTool(ctx, "test_tool", map[string]interface{}{
		"param": "value",
	})

	assert.NoError(t, err)
	assert.NotNil(t, result)

	// Test calling non-existent tool
	_, err = client.CallTool(ctx, "non_existent", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestParseMessage(t *testing.T) {
	tests := []struct {
		name        string
		data        string
		expectType  interface{}
		expectError bool
	}{
		{
			name: "parses request",
			data: `{
				"id": "req-1",
				"type": "request",
				"method": "test",
				"version": "1.0.0"
			}`,
			expectType:  &Request{},
			expectError: false,
		},
		{
			name: "parses response",
			data: `{
				"id": "resp-1",
				"type": "response",
				"result": {"data": "test"},
				"version": "1.0.0"
			}`,
			expectType:  &Response{},
			expectError: false,
		},
		{
			name: "parses notification",
			data: `{
				"type": "notify",
				"method": "event",
				"version": "1.0.0"
			}`,
			expectType:  &Notification{},
			expectError: false,
		},
		{
			name:        "fails on invalid JSON",
			data:        `{invalid json}`,
			expectError: true,
		},
		{
			name: "fails on unknown type",
			data: `{
				"type": "unknown",
				"version": "1.0.0"
			}`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, err := ParseMessage([]byte(tt.data))

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.IsType(t, tt.expectType, msg)
			}
		})
	}
}

func TestPing(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req Request
		_ = json.NewDecoder(r.Body).Decode(&req)

		if req.Method == "ping" {
			response := Response{
				ID:      req.ID,
				Type:    MessageTypeResponse,
				Version: ProtocolVersion,
				Result:  "pong",
			}
			_ = json.NewEncoder(w).Encode(response)
		} else {
			response := NewErrorResponse(req.ID, 404, "Method not found", nil)
			_ = json.NewEncoder(w).Encode(response)
		}
	}))
	defer server.Close()

	client := &Client{
		serverURL:   server.URL,
		httpClient:  &http.Client{Timeout: 5 * time.Second},
		timeout:     5 * time.Second,
		pendingReqs: make(map[string]chan *Response),
		tools:       make(map[string]Tool),
	}

	ctx := context.Background()
	err := client.Ping(ctx)
	assert.NoError(t, err)
}
