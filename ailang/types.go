// Package ailang provides a production-grade AI narration pipeline with strict
// language enforcement.  Every AIResponse.Text is guaranteed to be in the
// requested locale (fr or en) through a three-step pipeline:
//
//  1. Prompt injection — a language directive is prepended to every prompt.
//  2. Stopword validation — the response is checked with a fast,
//     dependency-free heuristic.
//  3. Retry + translation — one reinforced retry is attempted; if that still
//     fails the response is translated via the same LLM.
//
// All mismatches, retries, and translation fallbacks are observable via the
// EventReporter interface (wire in your Sentry client or pass nil for no-op).
//
// Example:
//
//	cfg := ailang.DefaultAIConfig()
//	guard := ailang.New(aiClient, cfg, nil, logger)
//
//	resp, err := guard.Generate(ctx, ailang.PromptInput{
//	    Prompt:   "Explique les résultats du plan.",
//	    Locale:   "fr",
//	    Metadata: map[string]any{"module": "insight"},
//	})
package ailang

import "context"

// PromptInput carries everything the pipeline needs to produce a localised
// AI response.
type PromptInput struct {
	// Prompt is the raw caller-supplied content.
	Prompt string
	// Locale is the required output language: "fr" (default) or "en".
	Locale string
	// Metadata is forwarded to observability events.
	// Recognised key: "module" (string) — surfaces in Sentry tags.
	Metadata map[string]any
}

// AIResponse is the structured result of a Generate call.
type AIResponse struct {
	// Text is the final, language-validated (or translated) content.
	Text string
	// Language holds the locale that was targeted (mirrors PromptInput.Locale).
	Language string
	// Raw is the unmodified first LLM response, kept for debugging.
	Raw string
	// Valid is true when Text passed language validation (or was translated).
	Valid bool
	// RetryCount records how many extra LLM calls were made (0 or 1).
	RetryCount int
}

// AIConfig controls the language enforcement behaviour.
type AIConfig struct {
	// MaxRetries is the number of reinforced retries before falling back to
	// translation.  Production default: 1.
	MaxRetries int
	// EnableTranslation allows the pipeline to use the LLM as a translator
	// when all retries are exhausted.  Production default: true.
	EnableTranslation bool
	// StrictLanguageCheck enables stopword-based language validation.
	// Set to false only in development / integration tests.
	StrictLanguageCheck bool
}

// DefaultAIConfig returns the recommended production defaults.
func DefaultAIConfig() AIConfig {
	return AIConfig{
		MaxRetries:          1,
		EnableTranslation:   true,
		StrictLanguageCheck: true,
	}
}

// RawCaller is the low-level interface satisfied by *aigateway.Client.
// Accepting an interface keeps this package independent and testable.
type RawCaller interface {
	Call(ctx context.Context, prompt string) (string, error)
}

// EventReporter is an optional observability hook.
//
// Wire in a real Sentry client:
//
//	type sentryReporter struct{}
//
//	func (sentryReporter) CaptureMessage(msg string, tags map[string]string) {
//	    sentry.WithScope(func(scope *sentry.Scope) {
//	        for k, v := range tags {
//	            scope.SetTag(k, v)
//	        }
//	        sentry.CaptureMessage(msg)
//	    })
//	}
//
// Pass nil to New() to use the built-in no-op reporter.
type EventReporter interface {
	CaptureMessage(msg string, tags map[string]string)
}
