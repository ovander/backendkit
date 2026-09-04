package aigateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// OllamaClient calls a local Ollama instance over HTTP and satisfies AIClient.
//
// It targets the non-streaming /api/generate endpoint.  Streaming is explicitly
// disabled (stream:false) so the response is a single JSON object.
//
// Usage:
//
//	c := aigateway.NewOllamaClient("http://localhost:11434", "llama3", 60, logger)
//	text, err := c.Call(ctx, prompt)
type OllamaClient struct {
	baseURL     string
	model       string
	httpTimeout time.Duration
	log         *logrus.Entry

	// overridable for tests
	apiGenerateURL string
}

// NewOllamaClient creates an OllamaClient.
//
//   - baseURL:    Ollama base URL, e.g. "http://localhost:11434".
//   - model:      Model name as known to Ollama, e.g. "llama3", "mistral".
//   - timeoutSec: HTTP timeout in seconds.  0 defaults to 60 s.
//   - logger:     Optional logrus entry; nil suppresses startup diagnostics.
func NewOllamaClient(baseURL, model string, timeoutSec int, logger *logrus.Entry) *OllamaClient {
	timeout := time.Duration(timeoutSec) * time.Second
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	base := strings.TrimRight(baseURL, "/")
	c := &OllamaClient{
		baseURL:        base,
		model:          model,
		httpTimeout:    timeout,
		log:            logger,
		apiGenerateURL: base + "/api/generate",
	}
	if logger != nil {
		logger.WithFields(logrus.Fields{
			"component": "aigateway.ollama",
			"base_url":  baseURL,
			"model":     model,
			"timeout_s": timeoutSec,
		}).Info("Ollama client initialised")
	}
	return c
}

// IsConfigured returns true when a model name and base URL are present.
func (c *OllamaClient) IsConfigured() bool {
	return c != nil && c.model != "" && c.baseURL != ""
}

// Model returns the configured model name.
func (c *OllamaClient) Model() string {
	if c == nil {
		return ""
	}
	return c.model
}

// ─────────────────────────────────────────────────────────────────────────────
// AIClient implementation
// ─────────────────────────────────────────────────────────────────────────────

// Call satisfies AIClient.  It sends prompt to POST /api/generate and returns
// the generated text.
func (c *OllamaClient) Call(ctx context.Context, prompt string) (string, error) {
	return c.call(ctx, prompt)
}

// CallWithMaxTokens is a convenience variant that maps maxTokens to Ollama's
// num_predict option.  It is NOT part of the AIClient interface but mirrors
// the *Client method for parity.
func (c *OllamaClient) CallWithMaxTokens(ctx context.Context, prompt string, maxTokens int) (string, error) {
	return c.callWithOptions(ctx, prompt, maxTokens)
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal HTTP logic
// ─────────────────────────────────────────────────────────────────────────────

// ollamaRequest is the JSON body for POST /api/generate.
type ollamaRequest struct {
	Model      string `json:"model"`
	Prompt     string `json:"prompt"`
	Stream     bool   `json:"stream"`
	NumPredict int    `json:"num_predict,omitempty"` // 0 = model default
}

// ollamaResponse is the non-streaming JSON response from /api/generate.
type ollamaResponse struct {
	Model    string `json:"model"`
	Response string `json:"response"`
	Done     bool   `json:"done"`
	Error    string `json:"error,omitempty"`
}

func (c *OllamaClient) call(ctx context.Context, prompt string) (string, error) {
	return c.callWithOptions(ctx, prompt, 0)
}

func (c *OllamaClient) callWithOptions(ctx context.Context, prompt string, numPredict int) (string, error) {
	reqBody, _ := json.Marshal(ollamaRequest{
		Model:      c.model,
		Prompt:     prompt,
		Stream:     false,
		NumPredict: numPredict,
	})

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.apiGenerateURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return "", fmt.Errorf("aigateway/ollama: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := (&http.Client{Timeout: c.httpTimeout}).Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("aigateway/ollama: http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("aigateway/ollama: HTTP %d: %s", resp.StatusCode, body)
	}

	var result ollamaResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("aigateway/ollama: decode response: %w", err)
	}
	if result.Error != "" {
		return "", fmt.Errorf("aigateway/ollama: provider error: %s", result.Error)
	}
	if !result.Done {
		return "", fmt.Errorf("aigateway/ollama: incomplete response (done=false); streaming is not supported")
	}
	return result.Response, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Test helper — mirrors ClientForTest in client.go
// ─────────────────────────────────────────────────────────────────────────────

// OllamaClientForTest creates an OllamaClient whose HTTP endpoint is pointed at
// serverURL for use with httptest.Server in unit tests.
func OllamaClientForTest(serverURL, model string) *OllamaClient {
	return &OllamaClient{
		baseURL:        serverURL,
		model:          model,
		httpTimeout:    5 * time.Second,
		apiGenerateURL: serverURL + "/api/generate",
	}
}
