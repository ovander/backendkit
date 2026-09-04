package ailang

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Translator uses the underlying RawCaller to translate text into a target
// locale.  It is JSON-aware: JSON documents are translated in a single LLM
// call that targets string values only, keeping keys and non-string values
// unchanged and the output structurally valid.
type Translator struct {
	caller RawCaller
}

// NewTranslator creates a Translator backed by caller.
func NewTranslator(caller RawCaller) *Translator {
	return &Translator{caller: caller}
}

// Translate returns text translated into locale.
//
// Behaviour:
//   - Plain text → single LLM call with BuildTranslationPrompt.
//   - JSON (object or array) → single LLM call instructed to translate string
//     values only; the result is validated as JSON before being returned.
//
// When the LLM call fails or returns an empty string, the original text is
// returned along with the error so the caller can decide how to handle it.
func (t *Translator) Translate(ctx context.Context, text, locale string) (string, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return "", nil
	}

	if looksLikeJSON(text) {
		return t.translateJSON(ctx, text, locale)
	}
	return t.translatePlain(ctx, text, locale)
}

// translatePlain sends a single translation prompt and returns the result.
func (t *Translator) translatePlain(ctx context.Context, text, locale string) (string, error) {
	prompt := BuildTranslationPrompt(text, locale)
	result, err := t.caller.Call(ctx, prompt)
	if err != nil {
		return text, fmt.Errorf("ailang: translator: %w", err)
	}
	result = strings.TrimSpace(result)
	if result == "" {
		return text, fmt.Errorf("ailang: translator: empty response from LLM")
	}
	return result, nil
}

// translateJSON sends a single LLM call that translates all string values
// inside the JSON document while preserving structure, then validates the
// output is still valid JSON.
//
// Fallback: if the LLM breaks the JSON structure, we attempt to extract a
// JSON object from the raw response before giving up and returning the
// original text.
func (t *Translator) translateJSON(ctx context.Context, raw, locale string) (string, error) {
	prompt := BuildTranslationPrompt(raw, locale)
	result, err := t.caller.Call(ctx, prompt)
	if err != nil {
		return raw, fmt.Errorf("ailang: translator (json): %w", err)
	}
	result = strings.TrimSpace(result)
	if result == "" {
		return raw, fmt.Errorf("ailang: translator (json): empty response from LLM")
	}

	// Happy path: LLM returned valid JSON directly.
	if json.Valid([]byte(result)) {
		return result, nil
	}

	// Soft fallback: strip markdown fences / prose the LLM may have added.
	extracted := extractJSONFragment(result)
	if json.Valid([]byte(extracted)) {
		return extracted, nil
	}

	// The LLM returned non-JSON; fall back to plain-text translation of the
	// string values only, then reconstruct the JSON manually.
	return t.translateJSONValues(ctx, raw, locale)
}

// translateJSONValues walks the decoded JSON tree and translates each string
// value individually.  This is more expensive (one LLM call per unique string)
// but is used only as a final fallback when translateJSON cannot produce valid
// JSON.
func (t *Translator) translateJSONValues(ctx context.Context, raw, locale string) (string, error) {
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return raw, fmt.Errorf("ailang: translator: cannot parse JSON: %w", err)
	}

	translated, err := t.walkTranslate(ctx, v, locale)
	if err != nil {
		return raw, err
	}

	out, err := json.Marshal(translated)
	if err != nil {
		return raw, fmt.Errorf("ailang: translator: cannot re-marshal JSON: %w", err)
	}
	return string(out), nil
}

// walkTranslate recursively translates string leaves in a decoded JSON tree.
func (t *Translator) walkTranslate(ctx context.Context, v any, locale string) (any, error) {
	switch val := v.(type) {
	case string:
		translated, err := t.translatePlain(ctx, val, locale)
		if err != nil {
			// Non-fatal: keep original string on error.
			return val, nil //nolint:nilerr
		}
		return translated, nil

	case map[string]any:
		result := make(map[string]any, len(val))
		for k, vv := range val {
			tv, err := t.walkTranslate(ctx, vv, locale)
			if err != nil {
				return v, err
			}
			result[k] = tv
		}
		return result, nil

	case []any:
		result := make([]any, len(val))
		for i, vv := range val {
			tv, err := t.walkTranslate(ctx, vv, locale)
			if err != nil {
				return v, err
			}
			result[i] = tv
		}
		return result, nil

	default:
		// numbers, booleans, nil — leave unchanged
		return v, nil
	}
}

// extractJSONFragment attempts to locate the first complete JSON object or
// array inside a string that may contain surrounding prose or markdown fences.
func extractJSONFragment(s string) string {
	// Try object first.
	if i := strings.Index(s, "{"); i != -1 {
		if j := strings.LastIndex(s, "}"); j > i {
			candidate := s[i : j+1]
			if json.Valid([]byte(candidate)) {
				return candidate
			}
		}
	}
	// Try array.
	if i := strings.Index(s, "["); i != -1 {
		if j := strings.LastIndex(s, "]"); j > i {
			candidate := s[i : j+1]
			if json.Valid([]byte(candidate)) {
				return candidate
			}
		}
	}
	return s
}
