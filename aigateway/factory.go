package aigateway

import (
	"github.com/sirupsen/logrus"

	"github.com/ovander/backendkit/ailang"
)

// GatewayConfig extends the existing Config with language-enforcement settings
// and the Ollama-specific base URL.
//
// Embed Config so every existing field (Provider, APIKey, Model, MaxTokens,
// TimeoutSec, AllowedModels) is inherited by name — no migration required for
// callers that already build a Config.
//
// All new fields have safe zero-value defaults (described below).
type GatewayConfig struct {
	Config // embedded — all existing Config fields are accessible directly

	// OllamaBaseURL is required when Config.Provider == "ollama".
	// Example: "http://localhost:11434"
	OllamaBaseURL string

	// Locale is the expected AI output language ("fr" or "en").
	// Empty string defaults to "fr" at runtime (system default).
	Locale string

	// MaxRetry is the maximum number of reinforced retries before the
	// translation fallback is attempted.
	// 0 (zero value) is treated as 1 (production default).
	MaxRetry int

	// EnableTranslation allows the pipeline to use the LLM as a translator
	// when all retries are exhausted.
	// true = enable (recommended for production).
	EnableTranslation bool

	// StrictLangCheck enables stopword-based language validation.
	// true = enforce (recommended); false = pass-through (useful in dev/test).
	StrictLangCheck bool

	// Reporter is an optional Sentry adapter.
	// nil → no-op reporter.
	Reporter ailang.EventReporter
}

// DefaultGatewayConfig returns a GatewayConfig with production-safe language
// enforcement defaults applied on top of the provided base Config.
//
// Provider routing and API keys must still be set by the caller.
func DefaultGatewayConfig(base Config) GatewayConfig {
	return GatewayConfig{
		Config:            base,
		MaxRetry:          1,
		EnableTranslation: true,
		StrictLangCheck:   true,
	}
}

// NewAIClient is the single entry point for creating a language-safe AI client.
//
// Internally it:
//  1. Selects the raw provider client based on cfg.Provider:
//     - "ollama"  → *OllamaClient (cfg.OllamaBaseURL required)
//     - "openai"  → *Client (cfg.APIKey required)
//     - "claude"  → *Client (cfg.APIKey required)  ← existing default
//  2. Wraps the raw client in a *SafeClient (language-enforcement decorator).
//  3. Returns the result as AIClient — a drop-in for any existing *Client usage.
//
// Migration from *Client to AIClient:
//
//	// Before
//	client := aigateway.New(cfg, logger)           // *Client
//	text, err := client.Call(ctx, prompt)
//
//	// After — zero change to call sites
//	client := aigateway.NewAIClient(aigateway.GatewayConfig{
//	    Config:           cfg,
//	    StrictLangCheck:  true,
//	    EnableTranslation: true,
//	}, logger)                                      // AIClient
//	text, err := client.Call(ctx, prompt)           // identical call
//
// Provider switch (e.g. Ollama):
//
//	client := aigateway.NewAIClient(aigateway.GatewayConfig{
//	    Config:            aigateway.Config{Provider: "ollama", Model: "llama3"},
//	    OllamaBaseURL:     "http://localhost:11434",
//	    StrictLangCheck:   true,
//	    EnableTranslation: true,
//	}, logger)
func NewAIClient(cfg GatewayConfig, logger *logrus.Entry) AIClient {
	// ── Step 1: raw provider client ──────────────────────────────────────────
	var raw AIClient
	switch cfg.Provider {
	case "ollama":
		raw = NewOllamaClient(cfg.OllamaBaseURL, cfg.Model, cfg.TimeoutSec, logger)
	default:
		// "openai", "claude", or anything else — use the existing *Client.
		raw = New(cfg.Config, logger)
	}

	// ── Step 2: language enforcement config with safe defaults ───────────────
	maxRetry := cfg.MaxRetry
	if maxRetry <= 0 {
		maxRetry = 1
	}
	aiCfg := ailang.AIConfig{
		MaxRetries:          maxRetry,
		EnableTranslation:   cfg.EnableTranslation,
		StrictLanguageCheck: cfg.StrictLangCheck,
	}

	// ── Step 3: wrap and return ───────────────────────────────────────────────
	return NewSafeClient(raw, aiCfg, cfg.Reporter, logger)
}
