package ailang

import "context"

// AIGateway is the top-level contract for language-safe AI generation.
//
// All implementations MUST guarantee that AIResponse.Text is in the locale
// requested by PromptInput.Locale.  When that guarantee cannot be met (e.g.
// the LLM is unreachable), Generate returns a non-nil error.
//
// The production implementation is LanguageGuard, created with New().
type AIGateway interface {
	Generate(ctx context.Context, input PromptInput) (AIResponse, error)
}
