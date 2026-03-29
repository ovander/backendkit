package aigateway

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ExtractJSON extracts the first complete JSON object from an AI response
// string that may contain surrounding prose or markdown code fences.
// It returns the raw JSON string (not parsed).
//
// Example:
//
//	raw := `Here is the analysis:\n{"score": 0.9, "summary": "ok"}\nHope this helps.`
//	jsonStr, err := aigateway.ExtractJSON(raw) // → `{"score": 0.9, "summary": "ok"}`
func ExtractJSON(response string) (string, error) {
	start := strings.Index(response, "{")
	end := strings.LastIndex(response, "}")
	if start == -1 || end == -1 || end <= start {
		return "", fmt.Errorf("aigateway: no valid JSON object found in AI response")
	}
	return response[start : end+1], nil
}

// ExtractJSONInto is a convenience wrapper that extracts JSON and unmarshals
// it into dst.
func ExtractJSONInto(response string, dst any) error {
	raw, err := ExtractJSON(response)
	if err != nil {
		return err
	}
	if err := json.Unmarshal([]byte(raw), dst); err != nil {
		return fmt.Errorf("aigateway: unmarshal AI JSON: %w", err)
	}
	return nil
}
