package socrate

// helpers.go — shared response-decoding helpers used by the extended client
// surface (profile, BFF token helpers, monitoring, dashboard, alerts, reports,
// settings). The original client.go/admin.go methods predate these helpers and
// keep their inline decoding; new methods use decodeJSON to stay terse.

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/ovander/backendkit/ctxutil"
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

// correlationIDHeader is the header Socrate reads a caller's request id from.
const correlationIDHeader = "X-Correlation-ID"

// maxCorrelationIDLength bounds the request id forwarded to Socrate.
const maxCorrelationIDLength = 128

// setCorrelationID forwards the request id in req's context
// (ctxutil.GetRequestID, set by httpware.RequestID) as X-Correlation-ID, so a
// call can be traced across the service and Socrate. Nothing is sent when
// there is no id, or when it is not a short run of printable ASCII: an id the
// HTTP client would refuse must never make the call itself fail.
func setCorrelationID(req *http.Request) {
	id := ctxutil.GetRequestID(req.Context())
	if id == "" || len(id) > maxCorrelationIDLength {
		return
	}
	for i := 0; i < len(id); i++ {
		if id[i] < 0x21 || id[i] > 0x7e {
			return
		}
	}
	req.Header.Set(correlationIDHeader, id)
}
