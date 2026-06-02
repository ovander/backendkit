package socrate

// helpers.go — shared response-decoding helpers used by the extended client
// surface (profile, BFF token helpers, monitoring, dashboard, alerts, reports,
// settings). The original client.go/admin.go methods predate these helpers and
// keep their inline decoding; new methods use decodeJSON to stay terse.

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// statusIn reports whether code is one of allowed. When allowed is empty it
// defaults to accepting only 200 OK.
func statusIn(code int, allowed []int) bool {
	if len(allowed) == 0 {
		return code == http.StatusOK
	}
	for _, a := range allowed {
		if code == a {
			return true
		}
	}
	return false
}

// decodeJSON reads resp, verifies the status is one of okCodes (default 200),
// and unmarshals the body into out. Pass out == nil to discard the body (for
// methods that only care about success). label is used to build clear errors,
// e.g. "list sessions HTTP 403: …".
func decodeJSON(resp *http.Response, label string, out interface{}, okCodes ...int) error {
	b, err := readBody(resp)
	if err != nil {
		return fmt.Errorf("read %s response: %w", label, err)
	}
	if !statusIn(resp.StatusCode, okCodes) {
		return fmt.Errorf("%s HTTP %d: %s", label, resp.StatusCode, b)
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			return fmt.Errorf("decode %s: %w", label, err)
		}
	}
	return nil
}
