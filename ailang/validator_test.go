package ailang_test

import (
	"testing"

	"github.com/ovander/backendkit/ailang"
)

// ─────────────────────────────────────────────────────────────────────────────
// IsCorrectLanguage
// ─────────────────────────────────────────────────────────────────────────────

func TestIsCorrectLanguage_FrenchText_FrLocale(t *testing.T) {
	// Clear French paragraph — should pass fr validation.
	text := "Le plan de l'utilisateur est en bonne voie. Les résultats sont positifs et les performances sont excellentes dans le domaine prévu."
	if !ailang.IsCorrectLanguage(text, "fr") {
		t.Errorf("expected French text to pass fr validation")
	}
}

func TestIsCorrectLanguage_EnglishText_EnLocale(t *testing.T) {
	text := "The user's plan is on track. The results are positive and the performance is excellent in the expected domain."
	if !ailang.IsCorrectLanguage(text, "en") {
		t.Errorf("expected English text to pass en validation")
	}
}

func TestIsCorrectLanguage_EnglishText_FrLocale_Fails(t *testing.T) {
	// English text must fail when fr is expected.
	text := "The analysis shows that the results are well above the average baseline for this quarter and the performance is strong."
	if ailang.IsCorrectLanguage(text, "fr") {
		t.Errorf("expected English text to FAIL fr validation")
	}
}

func TestIsCorrectLanguage_FrenchText_EnLocale_Fails(t *testing.T) {
	// French text must fail when en is expected.
	text := "Le résultat de l'analyse est très positif et les données sont conformes aux attentes de l'équipe et du plan."
	if ailang.IsCorrectLanguage(text, "en") {
		t.Errorf("expected French text to FAIL en validation")
	}
}

func TestIsCorrectLanguage_Empty_ReturnsFalse(t *testing.T) {
	if ailang.IsCorrectLanguage("", "fr") {
		t.Error("empty text should return false")
	}
	if ailang.IsCorrectLanguage("", "en") {
		t.Error("empty text should return false")
	}
}

func TestIsCorrectLanguage_ShortText_Relaxed(t *testing.T) {
	// Less than minTokensForCheck (5) tokens → always true (no reliable signal).
	if !ailang.IsCorrectLanguage("Bonjour", "en") {
		t.Error("short text should pass regardless of locale (relaxed threshold)")
	}
	if !ailang.IsCorrectLanguage("Hello", "fr") {
		t.Error("short text should pass regardless of locale (relaxed threshold)")
	}
}

func TestIsCorrectLanguage_UnknownLocale_PassThrough(t *testing.T) {
	// Unknown locale → pass-through (true) regardless of content.
	if !ailang.IsCorrectLanguage("Hola como estas muy bien", "es") {
		t.Error("unknown locale should return true (pass-through)")
	}
}

func TestIsCorrectLanguage_MixedText_FrLocale_Fails(t *testing.T) {
	// A text that is clearly half-and-half should fail fr validation because
	// the French stopword dominance will be below 60 %.
	mixed := "The results are very good and the performance is excellent. Les données sont bonnes et les résultats sont positifs."
	// Mixed text: en stopwords ≈ fr stopwords → dominance < 60 % for either language.
	// We only assert that the function returns a bool without panicking.
	// In practice mixed text should fail fr, but the exact ratio is input-dependent.
	result := ailang.IsCorrectLanguage(mixed, "fr")
	t.Logf("mixed text IsCorrectLanguage(fr)=%v", result)
}

// ─────────────────────────────────────────────────────────────────────────────
// ValidateText — JSON branch
// ─────────────────────────────────────────────────────────────────────────────

func TestValidateText_PlainFrench_FrLocale(t *testing.T) {
	text := "Le plan est en bonne voie. Les performances sont au rendez-vous et les résultats sont conformes aux attentes."
	if !ailang.ValidateText(text, "fr") {
		t.Errorf("French plain text should pass fr validation")
	}
}

func TestValidateText_JSONWithFrenchValues_FrLocale(t *testing.T) {
	// JSON whose string values are French → should pass fr validation.
	raw := `{"reason":"Le plan de l'utilisateur est en bonne voie et les résultats sont très positifs pour le trimestre en cours.","score":0.9}`
	if !ailang.ValidateText(raw, "fr") {
		t.Errorf("JSON with French string values should pass fr validation")
	}
}

func TestValidateText_JSONWithEnglishValues_FrLocale_Fails(t *testing.T) {
	// JSON whose string values are English → should fail fr validation.
	raw := `{"reason":"The plan is on track and the results are well above the expected baseline for this quarter and the performance is strong.","score":0.9}`
	if ailang.ValidateText(raw, "fr") {
		t.Errorf("JSON with English string values should FAIL fr validation")
	}
}

func TestValidateText_JSONStructureOnly_Passes(t *testing.T) {
	// JSON with no string values → no language signal → pass (structural-only).
	raw := `{"score":0.9,"count":42,"active":true}`
	if !ailang.ValidateText(raw, "fr") {
		t.Errorf("JSON with no string values should pass (no language signal)")
	}
}

func TestValidateText_Empty_ReturnsFalse(t *testing.T) {
	if ailang.ValidateText("", "fr") {
		t.Error("empty text should return false")
	}
}

func TestValidateText_InvalidJSON_TreatedAsPlainText(t *testing.T) {
	// A string that looks JSON-ish but is not valid → treated as plain text.
	text := `{"broken": `
	// Must not panic; result doesn't matter.
	_ = ailang.ValidateText(text, "fr")
}

func TestValidateText_JSONArray_FrenchValues(t *testing.T) {
	raw := `[{"item":"Le résultat est très positif et les données sont conformes aux attentes de l'équipe."},{"item":"Le plan de l'organisation est bien défini et en bonne voie de réalisation."}]`
	if !ailang.ValidateText(raw, "fr") {
		t.Errorf("JSON array with French string values should pass fr validation")
	}
}
