package aigateway

import "context"

// AIClient is the shared interface for all AI provider implementations in this
// package.  The existing *Client already satisfies it through structural typing
// — no modification to client.go is needed or made.
//
// Downstream code that currently holds a *Client can switch to AIClient at its
// own pace; both compile and behave identically for the Call method.
//
// Implementations in this package:
//   - *Client       — OpenAI / Anthropic Claude (cloud, existing)
//   - *OllamaClient — local Ollama instance (new)
//   - *SafeClient   — language-enforcement decorator (new, wraps any AIClient)
type AIClient interface {
	Call(ctx context.Context, prompt string) (string, error)
}
