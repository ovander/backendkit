package aigateway_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ovander/backendkit/aigateway"
)

func claudeServer(text string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"content": []map[string]string{{"type": "text", "text": text}},
		})
	}))
}

func openAIServer(text string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"choices": []map[string]interface{}{
				{"message": map[string]string{"content": text}},
			},
		})
	}))
}

func TestClient_CallClaude(t *testing.T) {
	srv := claudeServer("hello from claude")
	defer srv.Close()

	c := aigateway.ClientForTest("claude", "test-key", srv.URL)
	got, err := c.Call(context.Background(), "say hi")
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if got != "hello from claude" {
		t.Errorf("got %q, want 'hello from claude'", got)
	}
}

func TestClient_CallOpenAI(t *testing.T) {
	srv := openAIServer("hello from openai")
	defer srv.Close()

	c := aigateway.ClientForTest("openai", "test-key", srv.URL)
	got, err := c.Call(context.Background(), "say hi")
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if got != "hello from openai" {
		t.Errorf("got %q, want 'hello from openai'", got)
	}
}

func TestClient_IsConfigured(t *testing.T) {
	configured := aigateway.ClientForTest("claude", "key", "http://localhost")
	if !configured.IsConfigured() {
		t.Error("expected IsConfigured() = true when key is set")
	}
	notConfigured := aigateway.ClientForTest("claude", "", "http://localhost")
	if notConfigured.IsConfigured() {
		t.Error("expected IsConfigured() = false when key is empty")
	}
}

func TestClient_CallNoKey(t *testing.T) {
	c := aigateway.ClientForTest("claude", "", "http://localhost")
	_, err := c.Call(context.Background(), "hi")
	if err == nil {
		t.Error("expected error when API key is empty")
	}
}

func TestClient_UnsupportedProvider(t *testing.T) {
	c := aigateway.ClientForTest("groq", "key", "http://localhost")
	_, err := c.Call(context.Background(), "hi")
	if err == nil {
		t.Error("expected error for unsupported provider")
	}
}

func TestExtractJSON(t *testing.T) {
	input := `Here is the result: {"score": 1} done`
	got, err := aigateway.ExtractJSON(input)
	if err != nil {
		t.Fatalf("ExtractJSON: %v", err)
	}
	if got != `{"score": 1}` {
		t.Errorf("got %q", got)
	}
}

func TestExtractJSON_NoJSON(t *testing.T) {
	_, err := aigateway.ExtractJSON("no json here")
	if err == nil {
		t.Error("expected error when no JSON found")
	}
}

func TestExtractJSONInto(t *testing.T) {
	var out struct{ Score int }
	if err := aigateway.ExtractJSONInto(`{"score": 7}`, &out); err != nil {
		t.Fatalf("ExtractJSONInto: %v", err)
	}
	if out.Score != 7 {
		t.Errorf("Score = %d, want 7", out.Score)
	}
}
