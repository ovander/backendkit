package ailang_test

import (
	"context"
	"fmt"

	"github.com/ovander/backendkit/ailang"
)

// ExampleLanguageGuard_Generate_french demonstrates the standard usage from a
// service layer: inject a guard, call Generate, use AIResponse.Text.
func ExampleLanguageGuard_Generate_french() {
	// In production wire in your *aigateway.Client:
	//   guard := ailang.New(aiClient, ailang.DefaultAIConfig(), sentryReporter, logger)
	//
	// Here we use a pre-canned caller for the runnable example.
	caller := newSeqCaller("Le plan de l'utilisateur est en bonne voie. Les résultats sont positifs et les performances sont conformes aux attentes.")
	guard := ailang.New(caller, ailang.DefaultAIConfig(), nil, nil)

	resp, err := guard.Generate(context.Background(), ailang.PromptInput{
		Prompt:   "Génère une explication pour le plan de l'utilisateur.",
		Locale:   "fr",
		Metadata: map[string]any{"module": "insight"},
	})
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println("valid:", resp.Valid)
	fmt.Println("retries:", resp.RetryCount)

	// Output:
	// valid: true
	// retries: 0
}

// ExampleIsCorrectLanguage demonstrates the standalone language detector.
func ExampleIsCorrectLanguage() {
	frText := "Le plan de l'utilisateur est en bonne voie et les résultats sont positifs."
	enText := "The user's plan is on track and the results are looking positive."

	fmt.Println(ailang.IsCorrectLanguage(frText, "fr")) // true
	fmt.Println(ailang.IsCorrectLanguage(frText, "en")) // false
	fmt.Println(ailang.IsCorrectLanguage(enText, "en")) // true
	fmt.Println(ailang.IsCorrectLanguage(enText, "fr")) // false

	// Output:
	// true
	// false
	// true
	// false
}

// ExampleValidateText_json demonstrates JSON-aware language validation.
func ExampleValidateText_json() {
	frJSON := `{"reason":"Le plan de l'utilisateur est en bonne voie et les résultats sont très positifs.","score":0.9}`
	enJSON := `{"reason":"The plan is on track and the results are positive for this quarter.","score":0.9}`

	fmt.Println(ailang.ValidateText(frJSON, "fr")) // true
	fmt.Println(ailang.ValidateText(enJSON, "fr")) // false

	// Output:
	// true
	// false
}

// ExampleBuildPrompt demonstrates how the prompt builder injects the language
// directive.
func ExampleBuildPrompt() {
	prompt := ailang.BuildPrompt(ailang.PromptInput{
		Prompt: "Analyse le plan.",
		Locale: "fr",
	})
	// The directive is prepended; the original prompt appears at the end.
	fmt.Println(len(prompt) > len("Analyse le plan."))

	// Output:
	// true
}
