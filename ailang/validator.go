package ailang

import (
	"encoding/json"
	"strings"
	"unicode"
)

// ─────────────────────────────────────────────────────────────────────────────
// Stopword tables
// ─────────────────────────────────────────────────────────────────────────────

// frStopwords contains high-frequency French function words: articles,
// prepositions, conjunctions, and pronouns that are absent (or very rare) in
// English.  They are the most reliable signal for French text.
var frStopwords = map[string]struct{}{
	// articles
	"le": {}, "la": {}, "les": {}, "un": {}, "une": {}, "des": {},
	// contracted articles / prepositions
	"du": {}, "au": {}, "aux": {},
	// prepositions
	"de": {}, "en": {}, "dans": {}, "sur": {}, "avec": {}, "pour": {},
	"par": {}, "vers": {}, "sans": {}, "sous": {},
	// conjunctions
	"et": {}, "ou": {}, "mais": {}, "donc": {}, "car": {}, "ni": {},
	"que": {}, "qui": {}, "dont": {}, "quand": {}, "comme": {},
	// pronouns
	"je": {}, "tu": {}, "il": {}, "elle": {}, "nous": {}, "vous": {},
	"ils": {}, "elles": {}, "se": {}, "ce": {}, "cela": {}, "on": {},
	// adverbs / negation
	"ne": {}, "pas": {}, "plus": {}, "très": {}, "bien": {}, "aussi": {},
	// common verbs (inflected forms that appear often)
	"est": {}, "sont": {}, "était": {}, "avoir": {}, "être": {},
	// determiners
	"cette": {}, "ces": {}, "son": {}, "sa": {}, "ses": {},
	"leur": {}, "leurs": {}, "mon": {}, "ma": {}, "mes": {},
	"ton": {}, "ta": {}, "tes": {},
}

// enStopwords contains high-frequency English function words that are absent
// (or very rare) in French.
var enStopwords = map[string]struct{}{
	// articles
	"the": {}, "a": {}, "an": {},
	// prepositions
	"in": {}, "on": {}, "at": {}, "to": {}, "for": {}, "of": {},
	"with": {}, "by": {}, "from": {}, "into": {}, "about": {},
	// conjunctions
	"and": {}, "or": {}, "but": {}, "if": {}, "than": {}, "though": {},
	"that": {}, "which": {}, "when": {}, "while": {},
	// pronouns
	"it": {}, "its": {}, "they": {}, "them": {}, "their": {},
	"we": {}, "our": {}, "you": {}, "your": {},
	"he": {}, "she": {}, "his": {}, "her": {}, "this": {}, "these": {},
	// to-be / auxiliaries
	"is": {}, "are": {}, "was": {}, "were": {}, "be": {}, "been": {},
	"being": {}, "have": {}, "has": {}, "had": {}, "do": {}, "does": {},
	"did": {}, "will": {}, "would": {}, "could": {}, "should": {},
	"may": {}, "might": {}, "shall": {}, "can": {},
	// common adverbs / negation
	"not": {}, "also": {}, "very": {}, "just": {}, "as": {},
}

// ─────────────────────────────────────────────────────────────────────────────
// Language detection
// ─────────────────────────────────────────────────────────────────────────────

// IsCorrectLanguage reports whether text appears to be written in locale.
//
// Algorithm: tokenise → count stopword hits per language → require a minimum
// dominance ratio of the target language.
//
// Properties:
//   - Zero external dependencies.
//   - Deterministic for the same input.
//   - O(n) in the number of tokens.
//   - Handles short texts gracefully (relaxed for < minTokens words).
//
// Supported locales: "fr", "en".  Any other locale returns true (pass-through).
func IsCorrectLanguage(text string, locale string) bool {
	if text == "" {
		return false
	}
	if locale != "fr" && locale != "en" {
		return true
	}

	words := tokenize(text)
	if len(words) < minTokensForCheck {
		// Too short for a reliable heuristic; optimistically pass.
		return true
	}

	frScore, enScore := countStopwords(words)
	total := frScore + enScore
	if total == 0 {
		// No recognised stopwords — cannot determine language; pass.
		return true
	}

	switch locale {
	case "fr":
		return float64(frScore)/float64(total) >= dominanceThreshold
	case "en":
		return float64(enScore)/float64(total) >= dominanceThreshold
	}
	return true
}

// ValidateText performs language validation, with special handling for JSON:
// for JSON input it validates only the concatenation of all string values
// (ignoring keys and non-string values), so structural tokens never skew the
// result.
func ValidateText(text, locale string) bool {
	text = strings.TrimSpace(text)
	if text == "" {
		return false
	}

	if looksLikeJSON(text) {
		corpus := collectJSONStrings(text)
		if corpus == "" {
			return true // no translatable content; structural-only JSON is fine
		}
		return IsCorrectLanguage(corpus, locale)
	}

	return IsCorrectLanguage(text, locale)
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

const (
	// minTokensForCheck is the minimum number of word tokens before we apply
	// the stopword heuristic.  Below this threshold the text is too short to
	// yield a reliable signal.
	minTokensForCheck = 5

	// dominanceThreshold is the minimum fraction of recognised stopwords that
	// must belong to the target language.  0.60 means "60 % of all stopword
	// hits must be in the target language".
	dominanceThreshold = 0.60
)

// tokenize splits text into lowercase alphabetic tokens.
func tokenize(text string) []string {
	words := make([]string, 0, 32)
	var buf strings.Builder
	for _, r := range strings.ToLower(text) {
		if unicode.IsLetter(r) {
			buf.WriteRune(r)
		} else if buf.Len() > 0 {
			words = append(words, buf.String())
			buf.Reset()
		}
	}
	if buf.Len() > 0 {
		words = append(words, buf.String())
	}
	return words
}

// countStopwords returns (frenchHits, englishHits) for a token slice.
func countStopwords(words []string) (int, int) {
	fr, en := 0, 0
	for _, w := range words {
		if _, ok := frStopwords[w]; ok {
			fr++
		}
		if _, ok := enStopwords[w]; ok {
			en++
		}
	}
	return fr, en
}

// looksLikeJSON returns true when s begins with '{' or '[' and is valid JSON.
func looksLikeJSON(s string) bool {
	s = strings.TrimSpace(s)
	return len(s) > 1 && (s[0] == '{' || s[0] == '[') && json.Valid([]byte(s))
}

// collectJSONStrings unmarshals raw JSON and returns all string values
// (recursively) as a single space-separated string, ignoring keys.
func collectJSONStrings(raw string) string {
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return ""
	}
	var sb strings.Builder
	gatherStrings(v, &sb)
	return strings.TrimSpace(sb.String())
}

// gatherStrings walks the decoded JSON value tree and writes string leaves.
func gatherStrings(v any, sb *strings.Builder) {
	switch val := v.(type) {
	case string:
		sb.WriteString(val)
		sb.WriteByte(' ')
	case map[string]any:
		for _, vv := range val {
			gatherStrings(vv, sb)
		}
	case []any:
		for _, vv := range val {
			gatherStrings(vv, sb)
		}
	}
	// numbers, booleans, nil — silently ignored
}
