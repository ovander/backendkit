package ailang

import "fmt"

// langLabel maps a locale code to a human-readable language name used inside
// prompts.
var langLabel = map[string]string{
	"fr": "French (français)",
	"en": "English",
}

// labelFor returns the human-readable language name for locale, falling back
// to the raw locale string when unknown.
func labelFor(locale string) string {
	if l, ok := langLabel[locale]; ok {
		return l
	}
	return locale
}

// BuildPrompt prepends a strict language directive to input.Prompt.
//
// The directive instructs the LLM to:
//   - Write the entire response in the target language.
//   - Treat any other language as a hard failure requiring a rewrite.
//
// The original prompt is appended verbatim after a blank line so the LLM
// receives the full context.
func BuildPrompt(input PromptInput) string {
	lang := labelFor(input.Locale)
	return fmt.Sprintf(`OUTPUT LANGUAGE RULE (mandatory):
- The response MUST be written entirely in %s.
- Every word, sentence, and punctuation mark must be in %s.
- Do NOT mix languages under any circumstances.
- If you cannot comply with this rule, your answer is invalid and must be rewritten from scratch in %s.

%s`, lang, lang, lang, input.Prompt)
}

// BuildRetryPrompt creates a reinforced prompt for a second attempt after a
// language-validation failure.  The original prompt is appended so the LLM
// has full context.
//
// The reinforced header makes the violation explicit and raises the urgency
// of compliance; this materially improves LLM compliance rates in practice.
func BuildRetryPrompt(input PromptInput) string {
	lang := labelFor(input.Locale)
	return fmt.Sprintf(`⚠️  CRITICAL LANGUAGE VIOLATION — REWRITE REQUIRED

Your previous response was REJECTED because it was not written in %s.

MANDATORY CORRECTION RULES:
1. Rewrite the entire answer in %s.
2. Every single word must be in %s — no exceptions, no mixing.
3. Do NOT include any words from any other language.
4. If you include a single non-%s word, the answer will be rejected again.

Original request (answer it entirely in %s):
%s`, lang, lang, lang, lang, lang, input.Prompt)
}

// BuildTranslationPrompt builds a one-shot translation prompt.
//
// For JSON input the LLM is instructed to translate only the string values
// while preserving keys, structure, and non-string values verbatim — ensuring
// the output remains valid JSON.
func BuildTranslationPrompt(text, locale string) string {
	lang := labelFor(locale)
	return fmt.Sprintf(`Translate the following text into %s.

TRANSLATION RULES:
- Output ONLY the translated content. No explanations, no preamble.
- If the input is a JSON object or array:
    • Translate ONLY the string values.
    • Leave all keys, numbers, booleans, and null values unchanged.
    • The output MUST be valid JSON with the same structure.
- Preserve formatting (newlines, bullet points, etc.) where present.
- Preserve proper nouns and technical terms that should not be translated.

Text to translate:
%s`, lang, text)
}
