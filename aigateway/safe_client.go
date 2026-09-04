package aigateway

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/ovander/backendkit/ailang"
)

// SafeClient is a transparent decorator that adds language enforcement to any
// AIClient.  It satisfies AIClient itself, so it is a drop-in replacement
// everywhere a *Client was previously used.
//
// Pipeline on every Call:
//  1. Extract locale from ctx (WithLocale / default "fr").
//  2. Inject language directive into prompt (ailang.BuildPrompt).
//  3. Delegate to inner.Call.
//  4. Validate response language (stopword heuristic, no external API).
//  5. Retry once with reinforced prompt if validation fails.
//  6. Translate via LLM as final fallback.
//  7. Return resp.Text — callers see no structural change.
//
// Observability: language mismatches, retries, and fallbacks are logged and
// forwarded to the EventReporter (Sentry adapter).  Pass nil for no-op.
type SafeClient struct {
	guard *ailang.LanguageGuard
}

// NewSafeClient wraps inner with language enforcement.
//
//   - inner:    any AIClient (*Client, *OllamaClient, or another SafeClient).
//   - cfg:      use ailang.DefaultAIConfig() for production defaults.
//   - reporter: optional Sentry adapter; nil → no-op.
//   - log:      optional logrus entry; nil → standard logger.
//
// Because ailang.RawCaller and AIClient share the exact same Call signature,
// inner satisfies RawCaller through Go's structural typing with no adapter.
func NewSafeClient(
	inner AIClient,
	cfg ailang.AIConfig,
	reporter ailang.EventReporter,
	log *logrus.Entry,
) *SafeClient {
	return &SafeClient{
		guard: ailang.New(inner, cfg, reporter, log),
	}
}

// Call satisfies AIClient.
//
// Locale is read from ctx via LocaleFromContext (default "fr").
// Module tag is read from ctx via WithModule (default "unknown").
//
// The returned string is guaranteed to be in the requested locale when
// ailang.AIConfig.StrictLanguageCheck is true.
func (s *SafeClient) Call(ctx context.Context, prompt string) (string, error) {
	resp, err := s.guard.Generate(ctx, ailang.PromptInput{
		Prompt: prompt,
		Locale: LocaleFromContext(ctx),
		Metadata: map[string]any{
			"module": moduleFromContext(ctx),
		},
	})
	if err != nil {
		return "", fmt.Errorf("aigateway/safe: %w", err)
	}
	return resp.Text, nil
}

// ResponseDetail calls the underlying guard and returns the full AIResponse so
// callers that need RetryCount, Valid, or Raw can access them.
// This method is NOT on the AIClient interface and is opt-in.
func (s *SafeClient) ResponseDetail(ctx context.Context, prompt string) (ailang.AIResponse, error) {
	return s.guard.Generate(ctx, ailang.PromptInput{
		Prompt: prompt,
		Locale: LocaleFromContext(ctx),
		Metadata: map[string]any{
			"module": moduleFromContext(ctx),
		},
	})
}
