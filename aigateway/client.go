// Package aigateway provides a shared HTTP client for calling external AI
// providers (OpenAI and Anthropic Claude) from any backend service.
//
// Configuration is injected via Config — no environment variables are read
// inside this package.  Callers (typically via cmd/server config loading)
// populate Config and pass it to New.
//
// Example:
//
//	cfg := aigateway.Config{
//	    Provider:  "claude",
//	    APIKey:    os.Getenv("ANTHROPIC_API_KEY"),
//	    Model:     "claude-sonnet-4-6",
//	    MaxTokens: 2000,
//	    TimeoutSec: 30,
//	}
//	ai := aigateway.New(cfg, logrus.WithField("component", "ai"))
//	result, err := ai.Call(ctx, prompt)
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

// Config holds all AI provider settings.
type Config struct {
	// Provider is "openai" or "claude".
	Provider string
	// APIKey is the provider API key.
	APIKey string
	// Model is the default model identifier (e.g. "claude-sonnet-4-6", "gpt-4").
	Model string
	// AllowedModels restricts which models may be used. Empty = any.
	AllowedModels []string
	// MaxTokens is the default maximum number of completion tokens.
	MaxTokens int
	// TimeoutSec is the HTTP timeout in seconds. Defaults to 30.
	TimeoutSec int
}

// Client is a shared AI gateway client. It is safe for concurrent use.
type Client struct {
	provider      string
	apiKey        string
	model         string
	allowedModels []string
	maxTokens     int
	httpTimeout   time.Duration
	log           *logrus.Entry

	openAIBaseURL string
	claudeBaseURL string
}

// New creates a Client from cfg. logger may be nil to suppress startup
// diagnostics.
func New(cfg Config, logger *logrus.Entry) *Client {
	timeout := time.Duration(cfg.TimeoutSec) * time.Second
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	c := &Client{
		provider:      cfg.Provider,
		apiKey:        cfg.APIKey,
		model:         cfg.Model,
		allowedModels: cfg.AllowedModels,
		maxTokens:     cfg.MaxTokens,
		httpTimeout:   timeout,
		log:           logger,
		openAIBaseURL: "https://api.openai.com/v1/chat/completions",
		claudeBaseURL: "https://api.anthropic.com/v1/messages",
	}

	if logger != nil {
		f := logrus.Fields{
			"component":  "ai-gateway",
			"provider":   cfg.Provider,
			"model":      cfg.Model,
			"max_tokens": cfg.MaxTokens,
			"timeout_s":  cfg.TimeoutSec,
		}
		if cfg.APIKey != "" {
			f["api_key"] = "configured"
		} else {
			f["api_key"] = "not configured"
		}
		if len(cfg.AllowedModels) > 0 {
			f["allowed_models"] = strings.Join(cfg.AllowedModels, ", ")
		}
		logger.WithFields(f).Info("AI gateway initialised")
	}
	return c
}

// IsConfigured returns true when an API key is present.
func (c *Client) IsConfigured() bool {
	return c != nil && c.apiKey != ""
}

// Provider returns the configured AI provider name.
func (c *Client) Provider() string {
	if c == nil {
		return ""
	}
	return c.provider
}

// Call sends prompt to the configured AI provider and returns the text
// completion.
func (c *Client) Call(ctx context.Context, prompt string) (string, error) {
	if c == nil || c.apiKey == "" {
		return "", fmt.Errorf("aigateway: API key not configured")
	}
	switch c.provider {
	case "openai":
		return c.callOpenAI(ctx, prompt, c.maxTokens)
	case "claude":
		return c.callClaude(ctx, prompt, c.maxTokens)
	default:
		return "", fmt.Errorf("aigateway: unsupported provider %q", c.provider)
	}
}

// CallWithMaxTokens sends prompt with a custom token ceiling.
func (c *Client) CallWithMaxTokens(ctx context.Context, prompt string, maxTokens int) (string, error) {
	if c == nil || c.apiKey == "" {
		return "", fmt.Errorf("aigateway: API key not configured")
	}
	switch c.provider {
	case "openai":
		return c.callOpenAI(ctx, prompt, maxTokens)
	case "claude":
		return c.callClaude(ctx, prompt, maxTokens)
	default:
		return "", fmt.Errorf("aigateway: unsupported provider %q", c.provider)
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Internal provider implementations
// ────────────────────────────────────────────────────────────────────────────

// maxAIResponseBytes caps how much of a provider response is read into memory,
// guarding against an oversized/hostile upstream body.
const maxAIResponseBytes = 10 << 20 // 10 MiB

func (c *Client) callOpenAI(ctx context.Context, prompt string, maxTokens int) (string, error) {
	body, _ := json.Marshal(map[string]interface{}{
		"model":       "gpt-4",
		"messages":    []map[string]string{{"role": "user", "content": prompt}},
		"max_tokens":  maxTokens,
		"temperature": 0.7,
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.openAIBaseURL, bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := (&http.Client{Timeout: c.httpTimeout}).Do(req)
	if err != nil {
		return "", fmt.Errorf("openai request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, maxAIResponseBytes))
		return "", fmt.Errorf("OpenAI API HTTP %d: %s", resp.StatusCode, b)
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxAIResponseBytes)).Decode(&result); err != nil {
		return "", fmt.Errorf("decode openai response: %w", err)
	}
	if len(result.Choices) == 0 {
		return "", fmt.Errorf("no response from OpenAI")
	}
	return result.Choices[0].Message.Content, nil
}

func (c *Client) callClaude(ctx context.Context, prompt string, maxTokens int) (string, error) {
	if len(c.allowedModels) > 0 {
		allowed := false
		for _, m := range c.allowedModels {
			if m == c.model {
				allowed = true
				break
			}
		}
		if !allowed {
			return "", fmt.Errorf("aigateway: model %q not in allowed list", c.model)
		}
	}

	body, _ := json.Marshal(map[string]interface{}{
		"model":      c.model,
		"messages":   []map[string]string{{"role": "user", "content": prompt}},
		"max_tokens": maxTokens,
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.claudeBaseURL, bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := (&http.Client{Timeout: c.httpTimeout}).Do(req)
	if err != nil {
		return "", fmt.Errorf("claude request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, maxAIResponseBytes))
		return "", fmt.Errorf("claude API HTTP %d: %s", resp.StatusCode, b)
	}

	var result struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxAIResponseBytes)).Decode(&result); err != nil {
		return "", fmt.Errorf("decode claude response: %w", err)
	}
	if len(result.Content) == 0 {
		return "", fmt.Errorf("no response from Claude")
	}
	return result.Content[0].Text, nil
}

// ────────────────────────────────────────────────────────────────────────────
// Test helpers
// ────────────────────────────────────────────────────────────────────────────

// ClientForTest creates a Client for unit testing. Both openAIBaseURL and
// claudeBaseURL are pointed at serverURL so tests use an httptest.Server
// without real HTTP calls. Pass apiKey="" to create an unconfigured client
// (IsConfigured → false).
func ClientForTest(provider, apiKey, serverURL string) *Client {
	return &Client{
		provider:      provider,
		apiKey:        apiKey,
		model:         "claude-sonnet-4-6",
		maxTokens:     100,
		httpTimeout:   5 * time.Second,
		openAIBaseURL: serverURL,
		claudeBaseURL: serverURL,
	}
}
