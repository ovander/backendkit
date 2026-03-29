// Package ainarration provides a generic LRU+TTL cache for AI narration results
// and the data types shared between the cache and its consumers.
//
// Domain-specific types (NarrationContext, NarrationType, prompt builders) stay
// in the consumer application.  This package supplies only the infrastructure.
package ainarration

// NarrationOutput is the generic result stored in the cache. Callers embed or
// wrap this in their domain-specific response types.
type NarrationOutput struct {
	// Narrative is the main AI-generated text.
	Narrative string `json:"narrative"`
	// Metadata carries arbitrary key-value pairs (provider name, tokens used,
	// latency ms, model, etc.).  Values must be JSON-serialisable.
	Metadata map[string]any `json:"metadata,omitempty"`
}
