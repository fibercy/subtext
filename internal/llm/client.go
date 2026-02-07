// Package llm provides integration with Ollama for LLM-based text generation.
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	DefaultBaseURL = "http://localhost:11434"
	DefaultModel   = "qwen3:8b"
)

// Client provides access to Ollama API
type Client struct {
	baseURL    string
	model      string
	httpClient *http.Client
}

// ClientOption configures the client
type ClientOption func(*Client)

// WithBaseURL sets a custom Ollama base URL
func WithBaseURL(url string) ClientOption {
	return func(c *Client) {
		c.baseURL = url
	}
}

// WithModel sets the model to use
func WithModel(model string) ClientOption {
	return func(c *Client) {
		c.model = model
	}
}

// NewClient creates a new Ollama client
func NewClient(opts ...ClientOption) *Client {
	c := &Client{
		baseURL: DefaultBaseURL,
		model:   DefaultModel,
		httpClient: &http.Client{
			Timeout: 120 * time.Second,
		},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// GenerateRequest is the request body for /api/generate
type GenerateRequest struct {
	Model       string          `json:"model"`
	Prompt      string          `json:"prompt"`
	Stream      bool            `json:"stream"`
	Options     GenerateOptions `json:"options,omitempty"`
	Raw         bool            `json:"raw,omitempty"`
	Logprobs    bool            `json:"logprobs,omitempty"`
	TopLogprobs int             `json:"top_logprobs,omitempty"`
}

// GenerateOptions controls generation parameters
type GenerateOptions struct {
	Temperature float64  `json:"temperature,omitempty"`
	TopK        int      `json:"top_k,omitempty"`
	TopP        float64  `json:"top_p,omitempty"`
	NumPredict  int      `json:"num_predict,omitempty"`
	Stop        []string `json:"stop,omitempty"`
	Seed        int      `json:"seed,omitempty"`
}

// LogprobToken represents a single token with its log probability in top_logprobs
type LogprobToken struct {
	Token   string  `json:"token"`
	Logprob float64 `json:"logprob"`
	Bytes   []byte  `json:"bytes,omitempty"`
}

// LogprobItem represents a single token analysis from the logprobs array
type LogprobItem struct {
	Token       string         `json:"token"`
	Logprob     float64        `json:"logprob"`
	Bytes       []byte         `json:"bytes,omitempty"`
	TopLogprobs []LogprobToken `json:"top_logprobs,omitempty"`
}

// GenerateResponse is the response from /api/generate
type GenerateResponse struct {
	Model     string          `json:"model"`
	Response  string          `json:"response"`
	Done      bool            `json:"done"`
	Context   []int           `json:"context,omitempty"`
	CreatedAt string          `json:"created_at"`
	Logprobs  json.RawMessage `json:"logprobs,omitempty"`
}

// ParseLogprobs parses the raw logprobs JSON into structured LogprobItems
func (r *GenerateResponse) ParseLogprobs() ([]LogprobItem, error) {
	if len(r.Logprobs) == 0 {
		return nil, nil
	}
	var items []LogprobItem
	if err := json.Unmarshal(r.Logprobs, &items); err != nil {
		return nil, fmt.Errorf("failed to parse logprobs: %w", err)
	}
	return items, nil
}

// TokenizeRequest is the request body for tokenization
type TokenizeRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
}

// TokenizeResponse contains token IDs
type TokenizeResponse struct {
	Tokens []int `json:"tokens"`
}

// Generate performs text generation
func (c *Client) Generate(ctx context.Context, prompt string, opts GenerateOptions, logprobs bool) (*GenerateResponse, error) {
	fmt.Printf("[LLM Req] Prompt: %s\n", prompt)
	req := GenerateRequest{
		Model:       c.model,
		Prompt:      prompt,
		Stream:      false,
		Raw:         true,
		Options:     opts,
		Logprobs:    logprobs,
		TopLogprobs: 20,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/api/generate", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ollama returned status %d: %s", resp.StatusCode, string(body))
	}

	var result GenerateResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	fmt.Printf("[LLM Resp] Response: %s\n", result.Response)
	return &result, nil
}

// GenerateWithLogprobs generates text and returns token logprobs for constrained decoding
// This uses streaming to get token-by-token output
func (c *Client) GenerateWithLogprobs(ctx context.Context, prompt string, opts GenerateOptions) ([]TokenLogprob, error) {
	fmt.Printf("[LLM Req] Prompt (Stream): %s\n", prompt)
	req := GenerateRequest{
		Model:   c.model,
		Prompt:  prompt,
		Stream:  true,
		Options: opts,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/api/generate", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ollama returned status %d: %s", resp.StatusCode, string(body))
	}

	var tokens []TokenLogprob
	decoder := json.NewDecoder(resp.Body)
	for {
		var chunk struct {
			Response string `json:"response"`
			Done     bool   `json:"done"`
		}
		if err := decoder.Decode(&chunk); err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("failed to decode stream: %w", err)
		}

		if chunk.Response != "" {
			tokens = append(tokens, TokenLogprob{
				Token: chunk.Response,
			})
		}

		if chunk.Done {
			break
		}
	}

	return tokens, nil
}

// TokenLogprob represents a token with its log probability
type TokenLogprob struct {
	Token   string
	Logprob float64
}

// Tokenize converts text to token IDs
func (c *Client) Tokenize(ctx context.Context, text string) ([]int, error) {
	req := TokenizeRequest{
		Model:  c.model,
		Prompt: text,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/api/tokenize", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Note: Ollama may not support /api/tokenize for all models
	// Fall back to character-level if not available
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("tokenize endpoint not available")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ollama returned status %d: %s", resp.StatusCode, string(body))
	}

	var result TokenizeResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return result.Tokens, nil
}

// Ping checks if Ollama is running
func (c *Client) Ping(ctx context.Context) error {
	httpReq, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/api/tags", nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("ollama not reachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ollama returned status %d", resp.StatusCode)
	}

	return nil
}

// ListModels returns available models
func (c *Client) ListModels(ctx context.Context) ([]string, error) {
	httpReq, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/api/tags", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	models := make([]string, len(result.Models))
	for i, m := range result.Models {
		models[i] = m.Name
	}
	return models, nil
}
