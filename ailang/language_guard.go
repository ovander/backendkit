package ailang

import (
	"context"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
)

// ─────────────────────────────────────────────────────────────────────────────
// LanguageGuard — production AIGateway implementation
// ─────────────────────────────────────────────────────────────────────────────

// LanguageGuard implements AIGateway with a deterministic three-step language
// enforcement pipeline:
//
//  1. Prompt injection  — language directive prepended to every prompt.
//  2. Response validation — fast stopword heuristic, zero external deps.
//  3. Retry → translate  — one reinforced retry; translation fallback if retry
//     also fails.
//
// All language violations are logged and reported via EventReporter (Sentry).
type LanguageGuard struct {
	caller     RawCaller
	translator *Translator
	cfg        AIConfig
	reporter   EventReporter
	log        *logrus.Entry
}

// New creates a production-ready LanguageGuard.
//
//   - caller: any *aigateway.Client (satisfies RawCaller).
//   - cfg: use DefaultAIConfig() for production.
//   - reporter: optional Sentry adapter; pass nil for no-op.
//   - log: optional logrus entry; pass nil for the standard logger.
func New(caller RawCaller, cfg AIConfig, reporter EventReporter, log *logrus.Entry) *LanguageGuard {
	if reporter == nil {
		reporter = noOpReporter{}
	}
	if log == nil {
		log = logrus.NewEntry(logrus.StandardLogger())
	}
	return &LanguageGuard{
		caller:     caller,
		translator: NewTranslator(caller),
		cfg:        cfg,
		reporter:   reporter,
		log:        log.WithField("component", "ailang.language_guard"),
	}
}

// Generate implements AIGateway.
//
// Pipeline:
//
//  1. Normalise locale (default "fr").
//  2. Inject language directive into prompt.
//  3. Call LLM.
//  4. Validate response language.
//     → OK  : return immediately (RetryCount=0, Valid=true).
//     → FAIL: log + Sentry event; continue to step 5.
//  5. Retry once with a reinforced prompt (if MaxRetries > 0).
//     → OK  : return (RetryCount=1, Valid=true).
//     → FAIL: log + Sentry event; continue to step 6.
//  6. Translate fallback (if EnableTranslation).
//     → OK  : return (Valid=true, RetryCount preserved).
//     → FAIL: return (Valid=false) — caller must decide how to surface this.
func (g *LanguageGuard) Generate(ctx context.Context, input PromptInput) (AIResponse, error) {
	if input.Locale == "" {
		input.Locale = "fr" // enforce default locale
	}

	// ── Step 1: first LLM call with language-enforced prompt ────────────────
	prompt := BuildPrompt(input)
	raw, err := g.caller.Call(ctx, prompt)
	if err != nil {
		return AIResponse{}, fmt.Errorf("ailang: generate: %w", err)
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return AIResponse{}, fmt.Errorf("ailang: generate: LLM returned empty response")
	}

	resp := AIResponse{
		Raw:      raw,
		Text:     raw,
		Language: input.Locale,
		Valid:    true,
	}

	// ── Step 2: validate language ────────────────────────────────────────────
	if !g.cfg.StrictLanguageCheck || ValidateText(raw, input.Locale) {
		return resp, nil
	}

	// Language mismatch on first attempt.
	g.emitMismatch(input, 0)

	// ── Step 3a: retry with reinforced prompt ────────────────────────────────
	if g.cfg.MaxRetries > 0 {
		retryPrompt := BuildRetryPrompt(input)
		retryRaw, retryErr := g.caller.Call(ctx, retryPrompt)
		resp.RetryCount = 1

		if retryErr == nil {
			retryRaw = strings.TrimSpace(retryRaw)
			if retryRaw != "" && ValidateText(retryRaw, input.Locale) {
				resp.Text = retryRaw
				resp.Raw = retryRaw
				resp.Valid = true
				g.log.WithFields(logrus.Fields{
					"locale":      input.Locale,
					"retry_count": 1,
					"module":      moduleOf(input),
				}).Info("ailang: language guard — retry succeeded")
				return resp, nil
			}
		}

		// Retry also failed.
		g.emitMismatch(input, 1)
	}

	// ── Step 3b: translation fallback ───────────────────────────────────────
	if g.cfg.EnableTranslation {
		translated, tErr := g.translator.Translate(ctx, raw, input.Locale)
		if tErr == nil && translated != "" {
			resp.Text = translated
			resp.Valid = true

			module := moduleOf(input)
			g.log.WithFields(logrus.Fields{
				"locale":      input.Locale,
				"retry_count": resp.RetryCount,
				"module":      module,
			}).Warn("ailang: language guard — translation fallback used")

			g.reporter.CaptureMessage("AI language mismatch — translation fallback used", map[string]string{
				"locale":      input.Locale,
				"retry_count": fmt.Sprintf("%d", resp.RetryCount),
				"module":      module,
			})
			return resp, nil
		}
	}

	// ── All strategies exhausted ─────────────────────────────────────────────
	resp.Valid = false
	g.log.WithFields(logrus.Fields{
		"locale":      input.Locale,
		"retry_count": resp.RetryCount,
		"module":      moduleOf(input),
	}).Error("ailang: language guard — all enforcement strategies failed; returning invalid response")

	g.reporter.CaptureMessage("AI language enforcement failed — all strategies exhausted", map[string]string{
		"locale":      input.Locale,
		"retry_count": fmt.Sprintf("%d", resp.RetryCount),
		"module":      moduleOf(input),
	})

	return resp, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

// emitMismatch logs a language mismatch at WARN level and fires a Sentry event.
func (g *LanguageGuard) emitMismatch(input PromptInput, retryCount int) {
	module := moduleOf(input)
	g.log.WithFields(logrus.Fields{
		"locale":      input.Locale,
		"retry_count": retryCount,
		"module":      module,
	}).Warn("ailang: language mismatch detected")

	g.reporter.CaptureMessage("AI language mismatch", map[string]string{
		"locale":      input.Locale,
		"retry_count": fmt.Sprintf("%d", retryCount),
		"module":      module,
	})
}

// moduleOf extracts the "module" tag from PromptInput.Metadata, used for
// Sentry tags and log fields.
func moduleOf(input PromptInput) string {
	if input.Metadata == nil {
		return "unknown"
	}
	if m, ok := input.Metadata["module"].(string); ok && m != "" {
		return m
	}
	return "unknown"
}

// ─────────────────────────────────────────────────────────────────────────────
// noOpReporter — used when no EventReporter is injected
// ─────────────────────────────────────────────────────────────────────────────

type noOpReporter struct{}

func (noOpReporter) CaptureMessage(_ string, _ map[string]string) {}
