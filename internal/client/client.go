// Package client provides an OpenAI-compatible chat completion client with
// streaming, retry/jitter, and usage capture. Implements the ProviderClient
// interface consumed by the agent runtime (internal/agentrt).
package client

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

// ErrUnsupportedProvider is returned when a provider kind has no implementation.
var ErrUnsupportedProvider = errors.New("unsupported provider kind")

// ErrProviderUnavailable wraps a non-retriable provider error.
type ErrProviderUnavailable struct {
	Status int
	Body   string
}

func (e ErrProviderUnavailable) Error() string {
	return fmt.Sprintf("provider unavailable (status %d): %s", e.Status, e.Body)
}

// ErrRetryable wraps a retriable error (429, 5xx) with backoff guidance.
type ErrRetryable struct {
	Status      int
	RetryAfter  time.Duration
	Attempt     int
	MaxAttempts int
}

func (e ErrRetryable) Error() string {
	return fmt.Sprintf("retryable error (status %d, attempt %d/%d)", e.Status, e.Attempt, e.MaxAttempts)
}

// Usage holds token counts from a completion response.
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// Message is a chat message in the OpenAI wire format.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ToolCall models a function-call tool choice in the response.
type ToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

// CompletionRequest is the request body for chat completions.
type CompletionRequest struct {
	Model       string         `json:"model"`
	Messages    []Message      `json:"messages"`
	Tools       []ToolDef      `json:"tools,omitempty"`
	Stream      bool           `json:"stream"`
	MaxTokens   int            `json:"max_tokens,omitempty"`
	Temperature float64        `json:"temperature,omitempty"`
}

// ToolDef is a function tool definition sent to the provider.
type ToolDef struct {
	Type     string `json:"type"`
	Function struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Parameters  any    `json:"parameters"`
	} `json:"function"`
}

// CompletionChoice is a single choice in a non-streaming response.
type CompletionChoice struct {
	Index        int       `json:"index"`
	Message      Message   `json:"message"`
	FinishReason string    `json:"finish_reason"`
	ToolCalls    []ToolCall `json:"tool_calls,omitempty"`
}

// CompletionResponse is the non-streaming response body.
type CompletionResponse struct {
	ID      string             `json:"id"`
	Object  string             `json:"object"`
	Model   string             `json:"model"`
	Choices []CompletionChoice `json:"choices"`
	Usage   Usage              `json:"usage"`
}

// StreamDelta is a single delta from a streaming response.
type StreamDelta struct {
	Type    string `json:"type"`
	Delta   struct {
		Role      string    `json:"role,omitempty"`
		Content   string    `json:"content,omitempty"`
		ToolCalls []ToolCall `json:"tool_calls,omitempty"`
	} `json:"delta,omitempty"`
	FinishReason *string `json:"finish_reason,omitempty"`
	Usage        *Usage  `json:"usage,omitempty"`
}

// StreamResponse is a single line from the SSE stream.
type StreamResponse struct {
	ID      string        `json:"id"`
	Object  string        `json:"object"`
	Model   string        `json:"model"`
	Choices []StreamDelta `json:"choices"`
}

// StreamResult holds a completed stream's accumulated content and usage.
type StreamResult struct {
	Content      string
	ToolCalls    []ToolCall
	FinishReason string
	Usage        Usage
}

// ProviderClient is the interface the agent runtime uses to call LLMs.
type ProviderClient interface {
	// ChatCompletion sends a non-streaming chat completion request.
	ChatCompletion(ctx context.Context, req CompletionRequest) (*CompletionResponse, error)
	// ChatCompletionStream sends a streaming request, calling onDelta for each
	// delta chunk. Returns accumulated result with usage.
	ChatCompletionStream(ctx context.Context, req CompletionRequest, onDelta func(StreamDelta) error) (*StreamResult, error)
	// Model returns the provider's configured model name.
	Model() string
}

// ClientConfig configures an OpenAI-compatible provider client.
type ClientConfig struct {
	BaseURL     string // e.g. https://api.openai.com/v1
	APIKey      string
	Model       string
	MaxRetries  int
	BackoffBase time.Duration
	BackoffMax  time.Duration
	JitterPct   float64 // 0.0–0.5
}

// Default config values.
const (
	DefaultMaxRetries  = 3
	DefaultBackoffBase = 1 * time.Second
	DefaultBackoffMax  = 30 * time.Second
	DefaultJitterPct   = 0.25
)

// client implements ProviderClient for OpenAI-compatible endpoints.
type client struct {
	baseURL     string
	apiKey      string
	model       string
	maxRetries  int
	backoffBase time.Duration
	backoffMax  time.Duration
	jitterPct   float64
	httpClient  *http.Client
}

// New creates a ProviderClient for an OpenAI-compatible provider.
func New(cfg ClientConfig) ProviderClient {
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = DefaultMaxRetries
	}
	if cfg.BackoffBase <= 0 {
		cfg.BackoffBase = DefaultBackoffBase
	}
	if cfg.BackoffMax <= 0 {
		cfg.BackoffMax = DefaultBackoffMax
	}
	if cfg.JitterPct <= 0 || cfg.JitterPct > 0.5 {
		cfg.JitterPct = DefaultJitterPct
	}
	return &client{
		baseURL:     strings.TrimRight(cfg.BaseURL, "/"),
		apiKey:      cfg.APIKey,
		model:       cfg.Model,
		maxRetries:  cfg.MaxRetries,
		backoffBase: cfg.BackoffBase,
		backoffMax:  cfg.BackoffMax,
		jitterPct:   cfg.JitterPct,
		httpClient:  &http.Client{Timeout: 5 * time.Minute},
	}
}

// NewForKind creates a provider client from a provider kind string. Currently
// only "openai-compatible" is implemented; "codex_sso" returns ErrUnsupportedProvider.
func NewForKind(kind string, cfg ClientConfig) (ProviderClient, error) {
	switch kind {
	case "openai-compatible":
		return New(cfg), nil
	case "codex_sso":
		return nil, ErrUnsupportedProvider
	default:
		return nil, fmt.Errorf("unknown provider kind: %s", kind)
	}
}

func (c *client) Model() string { return c.model }

func (c *client) ChatCompletion(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
	req.Stream = false
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("client: marshal request: %w", err)
	}

	resp, err := c.do(ctx, body, c.maxRetries)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result CompletionResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("client: decode response: %w", err)
	}
	return &result, nil
}

func (c *client) ChatCompletionStream(ctx context.Context, req CompletionRequest, onDelta func(StreamDelta) error) (*StreamResult, error) {
	req.Stream = true
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("client: marshal request: %w", err)
	}

	resp, err := c.do(ctx, body, c.maxRetries)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return c.readStream(ctx, resp.Body, onDelta)
}

func (c *client) do(ctx context.Context, body []byte, maxRetries int) (*http.Response, error) {
	var lastErr error
	for attempt := 1; attempt <= maxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/chat/completions", bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("client: create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+c.apiKey)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("client: do request: %w", err)
			// Network error — retry
			if attempt < maxRetries {
				c.backoff(attempt)
				continue
			}
			return nil, lastErr
		}

		switch resp.StatusCode {
		case http.StatusOK:
			return resp, nil
		case http.StatusTooManyRequests, http.StatusServiceUnavailable,
			http.StatusGatewayTimeout, http.StatusBadGateway:
			retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"))
			lastErr = ErrRetryable{
				Status:      resp.StatusCode,
				RetryAfter:  retryAfter,
				Attempt:     attempt,
				MaxAttempts: maxRetries,
			}
			resp.Body.Close()
			if attempt < maxRetries {
				wait := retryAfter
				if wait <= 0 {
					wait = c.backoffDuration(attempt)
				}
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(wait):
				}
				continue
			}
			return nil, lastErr
		default:
			// Non-retriable error
			var bodyBuf bytes.Buffer
			io.Copy(&bodyBuf, resp.Body)
			resp.Body.Close()
			return nil, ErrProviderUnavailable{
				Status: resp.StatusCode,
				Body:   bodyBuf.String(),
			}
		}
	}
	return nil, lastErr
}

func (c *client) readStream(ctx context.Context, r io.Reader, onDelta func(StreamDelta) error) (*StreamResult, error) {
	scanner := bufio.NewScanner(r)
	// Increase scanner buffer for large SSE lines.
	scanner.Buffer(make([]byte, 0, 1024*64), 1024*64)

	result := &StreamResult{}

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			break
		}

		var sr StreamResponse
		if err := json.Unmarshal([]byte(data), &sr); err != nil {
			return nil, fmt.Errorf("client: parse stream chunk: %w", err)
		}
		if len(sr.Choices) == 0 {
			continue
		}
		d := sr.Choices[0]

		if d.Delta.Content != "" {
			result.Content += d.Delta.Content
		}
		if len(d.Delta.ToolCalls) > 0 {
			result.ToolCalls = append(result.ToolCalls, d.Delta.ToolCalls...)
		}
		if d.FinishReason != nil {
			result.FinishReason = *d.FinishReason
		}
		if d.Usage != nil {
			result.Usage = *d.Usage
		}

		if err := onDelta(d); err != nil {
			return nil, err
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("client: read stream: %w", err)
	}
	return result, nil
}

func (c *client) backoff(attempt int) {
	d := c.backoffDuration(attempt)
	select {
	case <-time.After(d):
	}
}

func (c *client) backoffDuration(attempt int) time.Duration {
	// Exponential backoff: base * 2^(attempt-1)
	exp := float64(c.backoffBase) * math.Pow(2, float64(attempt-1))
	d := time.Duration(exp)
	if d > c.backoffMax {
		d = c.backoffMax
	}
	// Apply jitter: ± jitterPct
	jitter := time.Duration(float64(d) * c.jitterPct * (2*rand.Float64() - 1))
	return d + jitter
}

func parseRetryAfter(s string) time.Duration {
	if s == "" {
		return 0
	}
	var seconds int
	if _, err := fmt.Sscanf(s, "%d", &seconds); err == nil {
		return time.Duration(seconds) * time.Second
	}
	// RFC 850 date — skip parsing, return 0
	return 0
}
