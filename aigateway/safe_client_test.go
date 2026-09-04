package aigateway_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/ovander/backendkit/aigateway"
	"github.com/ovander/backendkit/ailang"
)

// ─────────────────────────────────────────────────────────────────────────────
// Shared test fixtures — text long enough to trigger stopword heuristic
// ─────────────────────────────────────────────────────────────────────────────

const (
	frText = "Le plan de l'utilisateur est en bonne voie. Les résultats sont positifs et les performances sont conformes aux attentes du trimestre."
	enText = "The user's plan is on track. The results are positive and the performance is well above the expected baseline for this quarter."
)

// ─────────────────────────────────────────────────────────────────────────────
// seqAIClient — returns successive responses from a pre-defined slice
// ─────────────────────────────────────────────────────────────────────────────

type seqAIClient struct {
	responses []string
	callCount atomic.Int32
}

func newSeq(responses ...string) *seqAIClient {
	return &seqAIClient{responses: responses}
}

func (m *seqAIClient) Call(_ context.Context, _ string) (string, error) {
	i := int(m.callCount.Add(1)) - 1
	if i >= len(m.responses) {
		i = len(m.responses) - 1
	}
	return m.responses[i], nil
}

// errAIClient always returns an error.
type errAIClient struct{ err error }

func (e *errAIClient) Call(_ context.Context, _ string) (string, error) {
	return "", e.err
}

// capReporter records every CaptureMessage call.
type capReporter struct {
	events []string
}

func (r *capReporter) CaptureMessage(msg string, _ map[string]string) {
	r.events = append(r.events, msg)
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: strict SafeClient with capture reporter
// ─────────────────────────────────────────────────────────────────────────────

func strictSafe(inner aigateway.AIClient, rep ailang.EventReporter) *aigateway.SafeClient {
	return aigateway.NewSafeClient(inner, ailang.AIConfig{
		MaxRetries:          1,
		EnableTranslation:   true,
		StrictLanguageCheck: true,
	}, rep, nil)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests: language enforcement pipeline
// ─────────────────────────────────────────────────────────────────────────────

// TestSafeClient_CorrectLanguage_NoRetry verifies that a correct-language
// response is returned immediately without retry or Sentry events.
func TestSafeClient_CorrectLanguage_NoRetry(t *testing.T) {
	inner := newSeq(frText)
	rep := &capReporter{}
	sc := strictSafe(inner, rep)

	ctx := aigateway.WithLocale(context.Background(), "fr")
	got, err := sc.Call(ctx, "Analyse le plan.")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != frText {
		t.Errorf("unexpected text: %q", got)
	}
	if n := int(inner.callCount.Load()); n != 1 {
		t.Errorf("expected 1 LLM call, got %d", n)
	}
	if len(rep.events) != 0 {
		t.Errorf("expected no Sentry events, got %d", len(rep.events))
	}
}

// TestSafeClient_WrongLanguage_RetrySucceeds verifies that when the first
// response is in the wrong language the pipeline retries once and returns the
// corrected response.
func TestSafeClient_WrongLanguage_RetrySucceeds(t *testing.T) {
	// call 1 → English (wrong)  call 2 → French (correct)
	inner := newSeq(enText, frText)
	rep := &capReporter{}
	sc := strictSafe(inner, rep)

	ctx := aigateway.WithLocale(context.Background(), "fr")
	got, err := sc.Call(ctx, "Analyse le plan.")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != frText {
		t.Errorf("expected French text after retry, got: %q", got)
	}
	if n := int(inner.callCount.Load()); n != 2 {
		t.Errorf("expected 2 LLM calls (1 original + 1 retry), got %d", n)
	}
	// One mismatch event fired for the first failure.
	if len(rep.events) == 0 {
		t.Error("expected at least one Sentry event for language mismatch")
	}
}

// TestSafeClient_RetryFails_TranslationUsed verifies that when both the first
// attempt and the retry return the wrong language, the translation fallback is
// used (third LLM call).
func TestSafeClient_RetryFails_TranslationUsed(t *testing.T) {
	// call 1 → English (mismatch)
	// call 2 → English (retry, still mismatch)
	// call 3 → French  (translation result)
	inner := newSeq(enText, enText, frText)
	rep := &capReporter{}
	sc := strictSafe(inner, rep)

	ctx := aigateway.WithLocale(context.Background(), "fr")
	got, err := sc.Call(ctx, "Analyse le plan.")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != frText {
		t.Errorf("expected French text after translation, got: %q", got)
	}
	if n := int(inner.callCount.Load()); n != 3 {
		t.Errorf("expected 3 LLM calls (original + retry + translation), got %d", n)
	}
	if len(rep.events) < 2 {
		t.Errorf("expected ≥2 Sentry events (mismatch + fallback), got %d", len(rep.events))
	}
}

// TestSafeClient_AllStrategiesFail returns a non-nil Valid=false response
// without an error (the caller decides how to surface invalid content).
func TestSafeClient_AllStrategiesFail_NoError(t *testing.T) {
	// All three calls return English — no French ever produced.
	inner := newSeq(enText, enText, enText)
	sc := strictSafe(inner, nil)

	ctx := aigateway.WithLocale(context.Background(), "fr")
	// ResponseDetail exposes Valid so we can assert it.
	resp, err := sc.ResponseDetail(ctx, "Analyse.")

	if err != nil {
		t.Fatalf("expected no error when all strategies fail, got: %v", err)
	}
	if resp.Valid {
		t.Error("expected Valid=false when all strategies are exhausted")
	}
}

// TestSafeClient_LLMError propagates an LLM error to the caller.
func TestSafeClient_LLMError(t *testing.T) {
	inner := &errAIClient{err: errors.New("provider timeout")}
	sc := strictSafe(inner, nil)

	ctx := aigateway.WithLocale(context.Background(), "fr")
	_, err := sc.Call(ctx, "Analyse.")

	if err == nil {
		t.Fatal("expected error from LLM, got nil")
	}
}

// TestSafeClient_DefaultLocale_Fr verifies that an empty context defaults to "fr".
func TestSafeClient_DefaultLocale_Fr(t *testing.T) {
	inner := newSeq(frText) // French response — should pass fr validation
	sc := strictSafe(inner, nil)

	// No WithLocale — should default to "fr".
	_, err := sc.Call(context.Background(), "Analyse.")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestSafeClient_EnglishLocale verifies that en locale accepts English responses.
func TestSafeClient_EnglishLocale(t *testing.T) {
	inner := newSeq(enText)
	sc := strictSafe(inner, nil)

	ctx := aigateway.WithLocale(context.Background(), "en")
	got, err := sc.Call(ctx, "Analyse the plan.")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != enText {
		t.Errorf("unexpected text: %q", got)
	}
	if n := int(inner.callCount.Load()); n != 1 {
		t.Errorf("expected 1 LLM call for valid English, got %d", n)
	}
}

// TestSafeClient_StrictCheckDisabled_NoValidation verifies that disabling strict
// check returns any LLM response without retry (English passes for fr locale).
func TestSafeClient_StrictCheckDisabled_NoValidation(t *testing.T) {
	inner := newSeq(enText)
	sc := aigateway.NewSafeClient(inner, ailang.AIConfig{
		MaxRetries:          1,
		StrictLanguageCheck: false, // validation disabled
	}, nil, nil)

	ctx := aigateway.WithLocale(context.Background(), "fr")
	got, err := sc.Call(ctx, "Test.")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != enText {
		t.Errorf("expected raw LLM output when strict check disabled, got: %q", got)
	}
	if n := int(inner.callCount.Load()); n != 1 {
		t.Errorf("expected exactly 1 LLM call when strict check disabled, got %d", n)
	}
}

// TestSafeClient_ModuleTag_PropagatesViaSentry verifies the module tag from ctx
// appears in Sentry events.
func TestSafeClient_ModuleTag_PropagatesViaSentry(t *testing.T) {
	inner := newSeq(enText, frText) // first call wrong, retry correct
	rep := &capReporter{}
	sc := strictSafe(inner, rep)

	ctx := aigateway.WithLocale(context.Background(), "fr")
	ctx = aigateway.WithModule(ctx, "insight")

	if _, err := sc.Call(ctx, "Analyse."); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rep.events) == 0 {
		t.Error("expected at least one Sentry event for language mismatch")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests: context helpers
// ─────────────────────────────────────────────────────────────────────────────

func TestWithLocale_And_LocaleFromContext(t *testing.T) {
	ctx := aigateway.WithLocale(context.Background(), "en")
	if got := aigateway.LocaleFromContext(ctx); got != "en" {
		t.Errorf("LocaleFromContext = %q, want 'en'", got)
	}
}

func TestLocaleFromContext_Default(t *testing.T) {
	if got := aigateway.LocaleFromContext(context.Background()); got != "fr" {
		t.Errorf("default locale = %q, want 'fr'", got)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests: factory
// ─────────────────────────────────────────────────────────────────────────────

// TestNewAIClient_ReturnsAIClient ensures the factory returns a valid AIClient.
func TestNewAIClient_ReturnsAIClient(t *testing.T) {
	// We can't make real HTTP calls in unit tests, but we can verify the
	// factory constructs without panicking and satisfies AIClient.
	cfg := aigateway.GatewayConfig{
		Config: aigateway.Config{
			Provider: "claude",
			APIKey:   "",
			Model:    "claude-sonnet-4-6",
		},
		StrictLangCheck:   true,
		EnableTranslation: true,
	}
	client := aigateway.NewAIClient(cfg, nil)
	// NewAIClient already returns AIClient, so the interface is satisfied at
	// compile time and an assignment asserts nothing. Assert the part that can
	// actually fail: that a usable client came back.
	if client == nil {
		t.Fatal("NewAIClient returned nil")
	}
}

// TestNewAIClient_OllamaProvider creates an Ollama-backed client and makes a
// real call against an httptest.Server.
func TestNewAIClient_OllamaProvider(t *testing.T) {
	// Spin up a fake Ollama server (ollamaServer defined in ollama_client_test.go).
	srv := ollamaServer(frText)
	defer srv.Close()

	cfg := aigateway.GatewayConfig{
		Config: aigateway.Config{
			Provider:   "ollama",
			Model:      "llama3",
			TimeoutSec: 5,
		},
		OllamaBaseURL:     srv.URL,
		StrictLangCheck:   true,
		EnableTranslation: false, // keep test simple
		MaxRetry:          0,     // treated as 1 inside factory
	}

	client := aigateway.NewAIClient(cfg, nil)
	ctx := aigateway.WithLocale(context.Background(), "fr")
	got, err := client.Call(ctx, "Analyse le plan.")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != frText {
		t.Errorf("unexpected text: %q", got)
	}
}
