package aigateway_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ovander/backendkit/aigateway"
)

// ─────────────────────────────────────────────────────────────────────────────
// Server helpers (also used by safe_client_test.go — same package)
// ─────────────────────────────────────────────────────────────────────────────

// ollamaServer creates an httptest.Server that returns a valid Ollama response
// containing responseText on any POST to /api/generate.
func ollamaServer(responseText string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/generate" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"model":    "llama3",
			"response": responseText,
			"done":     true,
		})
	}))
}

// ollamaErrorServer returns an HTTP 500 error body.
func ollamaErrorServer(statusCode int, body string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(statusCode)
		w.Write([]byte(body))
	}))
}

// ollamaProviderErrorServer returns HTTP 200 with an "error" field set.
func ollamaProviderErrorServer(errorMsg string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": errorMsg,
			"done":  false,
		})
	}))
}

// ollamaNotDoneServer returns HTTP 200 with done=false (simulates partial
// streaming response that leaked through).
func ollamaNotDoneServer(text string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"response": text,
			"done":     false, // simulates streaming leak
		})
	}))
}

// ─────────────────────────────────────────────────────────────────────────────
// OllamaClient tests
// ─────────────────────────────────────────────────────────────────────────────

func TestOllamaClient_Call_Success(t *testing.T) {
	srv := ollamaServer("Bonjour le monde")
	defer srv.Close()

	c := aigateway.OllamaClientForTest(srv.URL, "llama3")
	got, err := c.Call(context.Background(), "Say hello in French.")

	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if got != "Bonjour le monde" {
		t.Errorf("got %q, want 'Bonjour le monde'", got)
	}
}

func TestOllamaClient_Call_HTTPError(t *testing.T) {
	srv := ollamaErrorServer(http.StatusInternalServerError, "internal error")
	defer srv.Close()

	c := aigateway.OllamaClientForTest(srv.URL, "llama3")
	_, err := c.Call(context.Background(), "prompt")

	if err == nil {
		t.Fatal("expected error for HTTP 500, got nil")
	}
}

func TestOllamaClient_Call_ProviderError(t *testing.T) {
	srv := ollamaProviderErrorServer("model not found")
	defer srv.Close()

	c := aigateway.OllamaClientForTest(srv.URL, "llama3")
	_, err := c.Call(context.Background(), "prompt")

	if err == nil {
		t.Fatal("expected error for provider error field, got nil")
	}
}

func TestOllamaClient_Call_NotDone(t *testing.T) {
	srv := ollamaNotDoneServer("partial")
	defer srv.Close()

	c := aigateway.OllamaClientForTest(srv.URL, "llama3")
	_, err := c.Call(context.Background(), "prompt")

	if err == nil {
		t.Fatal("expected error when done=false, got nil")
	}
}

func TestOllamaClient_Call_ContextCancelled(t *testing.T) {
	srv := ollamaServer("hello")
	defer srv.Close()

	c := aigateway.OllamaClientForTest(srv.URL, "llama3")

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := c.Call(ctx, "prompt")
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
}

func TestOllamaClient_IsConfigured(t *testing.T) {
	configured := aigateway.OllamaClientForTest("http://localhost:11434", "llama3")
	if !configured.IsConfigured() {
		t.Error("expected IsConfigured=true when model and baseURL are set")
	}

	empty := aigateway.OllamaClientForTest("", "")
	if empty.IsConfigured() {
		t.Error("expected IsConfigured=false when model and baseURL are empty")
	}
}

func TestOllamaClient_CallWithMaxTokens(t *testing.T) {
	// Verify num_predict is marshalled into the request body.
	var capturedBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&capturedBody) //nolint:errcheck
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"response": "ok",
			"done":     true,
		})
	}))
	defer srv.Close()

	c := aigateway.OllamaClientForTest(srv.URL, "llama3")
	_, err := c.CallWithMaxTokens(context.Background(), "prompt", 256)
	if err != nil {
		t.Fatalf("CallWithMaxTokens: %v", err)
	}
	if v, ok := capturedBody["num_predict"]; !ok || v == nil {
		t.Error("expected num_predict to be set in request body")
	}
}

// TestOllamaClient_SatisfiesAIClient is a compile-time assertion encoded as a
// runtime test: assigning *OllamaClient to AIClient must compile.
func TestOllamaClient_SatisfiesAIClient(t *testing.T) {
	srv := ollamaServer("ok")
	defer srv.Close()
	var _ aigateway.AIClient = aigateway.OllamaClientForTest(srv.URL, "llama3")
}

// TestClient_SatisfiesAIClient verifies the existing *Client still satisfies
// the new AIClient interface — regression guard.
func TestClient_SatisfiesAIClient(t *testing.T) {
	c := aigateway.ClientForTest("claude", "key", "http://localhost")
	var _ aigateway.AIClient = c
}
