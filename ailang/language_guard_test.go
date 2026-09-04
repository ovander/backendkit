package ailang_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/ovander/backendkit/ailang"
)

// ─────────────────────────────────────────────────────────────────────────────
// Test doubles
// ─────────────────────────────────────────────────────────────────────────────

// seqCaller returns successive responses from a pre-defined slice.
// When the slice is exhausted it returns the last entry indefinitely.
type seqCaller struct {
	responses []string
	errors    []error
	calls     atomic.Int32
}

func newSeqCaller(responses ...string) *seqCaller {
	return &seqCaller{responses: responses}
}

func newErrCaller(err error) *seqCaller {
	return &seqCaller{errors: []error{err}}
}

func (s *seqCaller) Call(_ context.Context, _ string) (string, error) {
	i := int(s.calls.Add(1)) - 1
	if len(s.errors) > 0 {
		ei := i
		if ei >= len(s.errors) {
			ei = len(s.errors) - 1
		}
		if s.errors[ei] != nil {
			return "", s.errors[ei]
		}
	}
	if len(s.responses) == 0 {
		return "", nil
	}
	ri := i
	if ri >= len(s.responses) {
		ri = len(s.responses) - 1
	}
	return s.responses[ri], nil
}

// capturingReporter records the last CaptureMessage call for assertions.
type capturingReporter struct {
	lastMsg  string
	lastTags map[string]string
	count    int
}

func (r *capturingReporter) CaptureMessage(msg string, tags map[string]string) {
	r.lastMsg = msg
	r.lastTags = tags
	r.count++
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

const (
	clearFrench  = "Le plan de l'utilisateur est en bonne voie. Les résultats sont positifs et les performances sont excellentes dans le domaine prévu."
	clearEnglish = "The user's plan is on track. The results are positive and the performance is excellent in the expected domain for this quarter."
)

func strictCfg() ailang.AIConfig {
	return ailang.AIConfig{
		MaxRetries:          1,
		EnableTranslation:   true,
		StrictLanguageCheck: true,
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Core pipeline tests
// ─────────────────────────────────────────────────────────────────────────────

// TestGenerate_CorrectLanguage_NoRetry verifies that a correct-language response
// is returned immediately without any retry.
func TestGenerate_CorrectLanguage_NoRetry(t *testing.T) {
	caller := newSeqCaller(clearFrench)
	reporter := &capturingReporter{}
	guard := ailang.New(caller, strictCfg(), reporter, nil)

	resp, err := guard.Generate(context.Background(), ailang.PromptInput{
		Prompt: "Analyse le plan.",
		Locale: "fr",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Valid {
		t.Errorf("response should be Valid")
	}
	if resp.RetryCount != 0 {
		t.Errorf("expected RetryCount=0, got %d", resp.RetryCount)
	}
	if resp.Text != clearFrench {
		t.Errorf("unexpected Text: %q", resp.Text)
	}
	if resp.Language != "fr" {
		t.Errorf("expected Language=fr, got %q", resp.Language)
	}
	// No Sentry events should have been fired.
	if reporter.count != 0 {
		t.Errorf("expected 0 Sentry events, got %d", reporter.count)
	}
	// Only one LLM call should have been made.
	if got := int(caller.calls.Load()); got != 1 {
		t.Errorf("expected 1 LLM call, got %d", got)
	}
}

// TestGenerate_WrongLanguage_RetrySucceeds verifies the retry path: the first
// call returns English (wrong) and the retry returns French (correct).
func TestGenerate_WrongLanguage_RetrySucceeds(t *testing.T) {
	// First call → wrong language (English); second call → correct (French).
	caller := newSeqCaller(clearEnglish, clearFrench)
	reporter := &capturingReporter{}
	guard := ailang.New(caller, strictCfg(), reporter, nil)

	resp, err := guard.Generate(context.Background(), ailang.PromptInput{
		Prompt:   "Analyse le plan.",
		Locale:   "fr",
		Metadata: map[string]any{"module": "suggest"},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Valid {
		t.Errorf("response should be Valid after successful retry")
	}
	if resp.RetryCount != 1 {
		t.Errorf("expected RetryCount=1, got %d", resp.RetryCount)
	}
	if resp.Text != clearFrench {
		t.Errorf("unexpected Text after retry: %q", resp.Text)
	}
	// Should have emitted exactly one mismatch event (for the first failure).
	if reporter.count != 1 {
		t.Errorf("expected 1 Sentry event (mismatch on first call), got %d", reporter.count)
	}
	if reporter.lastTags["locale"] != "fr" {
		t.Errorf("expected Sentry tag locale=fr, got %q", reporter.lastTags["locale"])
	}
	if reporter.lastTags["module"] != "suggest" {
		t.Errorf("expected Sentry tag module=suggest, got %q", reporter.lastTags["module"])
	}
	// Two LLM calls expected: first attempt + one retry.
	if got := int(caller.calls.Load()); got != 2 {
		t.Errorf("expected 2 LLM calls, got %d", got)
	}
}

// TestGenerate_RetryFails_TranslationUsed verifies the translation fallback:
// both the first call and the retry return English, so translation is used.
// The translation call also returns clearFrench.
func TestGenerate_RetryFails_TranslationUsed(t *testing.T) {
	// call 1 → English (mismatch)
	// call 2 → English (retry, still mismatch)
	// call 3 → French  (translation prompt → correct French result)
	caller := newSeqCaller(clearEnglish, clearEnglish, clearFrench)
	reporter := &capturingReporter{}
	guard := ailang.New(caller, strictCfg(), reporter, nil)

	resp, err := guard.Generate(context.Background(), ailang.PromptInput{
		Prompt:   "Analyse le plan.",
		Locale:   "fr",
		Metadata: map[string]any{"module": "insight"},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Valid {
		t.Errorf("response should be Valid after translation fallback")
	}
	if resp.RetryCount != 1 {
		t.Errorf("expected RetryCount=1, got %d", resp.RetryCount)
	}
	if resp.Text != clearFrench {
		t.Errorf("unexpected Text after translation: %q", resp.Text)
	}
	// Two Sentry events: one for mismatch on first attempt, one for retry+translation.
	if reporter.count < 2 {
		t.Errorf("expected at least 2 Sentry events, got %d", reporter.count)
	}
	if reporter.lastTags["module"] != "insight" {
		t.Errorf("expected Sentry tag module=insight, got %q", reporter.lastTags["module"])
	}
	// Three LLM calls: original + retry + translation.
	if got := int(caller.calls.Load()); got != 3 {
		t.Errorf("expected 3 LLM calls, got %d", got)
	}
}

// TestGenerate_AllStrategiesFail_ReturnInvalid verifies that when every strategy
// fails (mismatch on all calls) the pipeline returns Valid=false without error.
func TestGenerate_AllStrategiesFail_ReturnInvalid(t *testing.T) {
	// All calls return English; translation also returns English.
	caller := newSeqCaller(clearEnglish, clearEnglish, clearEnglish)
	reporter := &capturingReporter{}
	guard := ailang.New(caller, strictCfg(), reporter, nil)

	resp, err := guard.Generate(context.Background(), ailang.PromptInput{
		Prompt: "Analyse le plan.",
		Locale: "fr",
	})

	if err != nil {
		t.Fatalf("expected no error (valid failure path), got: %v", err)
	}
	if resp.Valid {
		t.Errorf("expected Valid=false when all strategies fail")
	}
}

// TestGenerate_LLMError_ReturnsError verifies that an LLM error is propagated.
func TestGenerate_LLMError_ReturnsError(t *testing.T) {
	caller := newErrCaller(errors.New("provider timeout"))
	guard := ailang.New(caller, strictCfg(), nil, nil)

	_, err := guard.Generate(context.Background(), ailang.PromptInput{
		Prompt: "Test.",
		Locale: "fr",
	})

	if err == nil {
		t.Fatal("expected error from LLM, got nil")
	}
}

// TestGenerate_EmptyResponse_ReturnsError ensures an empty LLM response is
// treated as an error, not a valid empty string.
func TestGenerate_EmptyResponse_ReturnsError(t *testing.T) {
	caller := newSeqCaller("") // empty response
	guard := ailang.New(caller, strictCfg(), nil, nil)

	_, err := guard.Generate(context.Background(), ailang.PromptInput{
		Prompt: "Test.",
		Locale: "fr",
	})

	if err == nil {
		t.Fatal("expected error for empty LLM response")
	}
}

// TestGenerate_DefaultLocale verifies that an empty Locale defaults to "fr".
func TestGenerate_DefaultLocale(t *testing.T) {
	caller := newSeqCaller(clearFrench)
	guard := ailang.New(caller, strictCfg(), nil, nil)

	resp, err := guard.Generate(context.Background(), ailang.PromptInput{
		Prompt: "Analyse.", // no Locale set
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Language != "fr" {
		t.Errorf("expected default Language=fr, got %q", resp.Language)
	}
}

// TestGenerate_StrictCheckDisabled_NoValidation verifies that disabling strict
// checking skips language validation entirely (English passes for fr locale).
func TestGenerate_StrictCheckDisabled_NoValidation(t *testing.T) {
	cfg := ailang.AIConfig{
		MaxRetries:          1,
		EnableTranslation:   true,
		StrictLanguageCheck: false, // validation off
	}
	caller := newSeqCaller(clearEnglish)
	guard := ailang.New(caller, cfg, nil, nil)

	resp, err := guard.Generate(context.Background(), ailang.PromptInput{
		Prompt: "Test.",
		Locale: "fr",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Valid {
		t.Errorf("expected Valid=true when strict check is disabled")
	}
	if resp.RetryCount != 0 {
		t.Errorf("expected RetryCount=0 when strict check is disabled, got %d", resp.RetryCount)
	}
	// Only one LLM call.
	if got := int(caller.calls.Load()); got != 1 {
		t.Errorf("expected 1 LLM call, got %d", got)
	}
}

// TestGenerate_EnglishLocale_EnglishResponse verifies en locale works correctly.
func TestGenerate_EnglishLocale_EnglishResponse(t *testing.T) {
	caller := newSeqCaller(clearEnglish)
	guard := ailang.New(caller, strictCfg(), nil, nil)

	resp, err := guard.Generate(context.Background(), ailang.PromptInput{
		Prompt: "Analyse the plan.",
		Locale: "en",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Valid {
		t.Errorf("English response should be valid for en locale")
	}
	if resp.RetryCount != 0 {
		t.Errorf("expected RetryCount=0, got %d", resp.RetryCount)
	}
}

// TestGenerate_JSONResponse_FrenchValues verifies that JSON responses with
// French string values pass fr validation without a retry.
func TestGenerate_JSONResponse_FrenchValues(t *testing.T) {
	frJSON := `{"reason":"Le plan de l'utilisateur est en bonne voie et les résultats sont conformes aux attentes de l'équipe.","score":0.92}`
	caller := newSeqCaller(frJSON)
	guard := ailang.New(caller, strictCfg(), nil, nil)

	resp, err := guard.Generate(context.Background(), ailang.PromptInput{
		Prompt: "Analyse en JSON.",
		Locale: "fr",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Valid {
		t.Errorf("French JSON response should be valid for fr locale")
	}
	if resp.RetryCount != 0 {
		t.Errorf("expected RetryCount=0, got %d", resp.RetryCount)
	}
}

// TestGenerate_RawPreserved verifies that AIResponse.Raw holds the very first
// LLM response, even when translation was used.
func TestGenerate_RawPreserved(t *testing.T) {
	caller := newSeqCaller(clearEnglish, clearEnglish, clearFrench)
	guard := ailang.New(caller, strictCfg(), nil, nil)

	resp, err := guard.Generate(context.Background(), ailang.PromptInput{
		Prompt: "Analyse.",
		Locale: "fr",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Raw != clearEnglish {
		t.Errorf("expected Raw to be the first LLM response, got %q", resp.Raw)
	}
}
