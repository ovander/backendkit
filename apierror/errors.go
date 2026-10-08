// Package apierror provides structured HTTP error types for REST APIs.
// Use the constructor functions (NotFound, Unauthorized, ValidationError, etc.)
// rather than creating AppError values directly.
package apierror

import (
	"encoding/json"
	"net/http"
)

// AppError is the standard error type returned by services and handlers.
type AppError struct {
	Code string `json:"code"`
	Key  string `json:"key,omitempty"` // i18n key — frontend translates this
	// Message is the human-readable message. It is serialized to the client for
	// 4xx responses; for 5xx, WriteJSON replaces it with a generic status text
	// (and drops Details) so internal/dev-facing strings never leak. The original
	// Message is always available server-side via Error() for logging.
	Message    string `json:"message"`
	StatusCode int    `json:"-"`
	Details    any    `json:"details,omitempty"`
}

func (e *AppError) Error() string { return e.Message }

// WithKey returns the same error with the given i18n key set.
// Use this to tag errors for frontend localisation:
//
//	apierror.BadRequest("invalid store ID").WithKey("errors.invalidStoreId")
func (e *AppError) WithKey(key string) *AppError {
	e.Key = key
	return e
}

// WithDetails returns the same error with the given details set.
func (e *AppError) WithDetails(details any) *AppError {
	e.Details = details
	return e
}

// ErrorResponse wraps AppError for JSON API responses.
type ErrorResponse struct {
	Error AppError `json:"error"`
}

// NotFound returns a 404 error for a missing entity.
func NotFound(entity, id string) *AppError {
	return &AppError{
		Code:       "not_found",
		StatusCode: http.StatusNotFound,
		Message:    entity + " not found: " + id,
	}
}

// ValidationError returns a 422 error with optional details.
func ValidationError(msg string, details any) *AppError {
	return &AppError{
		Code:       "validation_error",
		StatusCode: http.StatusUnprocessableEntity,
		Message:    msg,
		Details:    details,
	}
}

// BadRequest returns a 400 error.
func BadRequest(msg string) *AppError {
	return &AppError{
		Code:       "bad_request",
		StatusCode: http.StatusBadRequest,
		Message:    msg,
	}
}

// Unauthorized returns a 401 error.
func Unauthorized(msg string) *AppError {
	return &AppError{
		Code:       "unauthorized",
		StatusCode: http.StatusUnauthorized,
		Message:    msg,
	}
}

// Forbidden returns a 403 error.
func Forbidden(msg string) *AppError {
	return &AppError{
		Code:       "forbidden",
		StatusCode: http.StatusForbidden,
		Message:    msg,
	}
}

// Conflict returns a 409 error.
func Conflict(msg string) *AppError {
	return &AppError{
		Code:       "conflict",
		StatusCode: http.StatusConflict,
		Message:    msg,
	}
}

// TooManyRequests returns a 429 error, typically for rate limiting.
func TooManyRequests(msg string) *AppError {
	return &AppError{
		Code:       "too_many_requests",
		StatusCode: http.StatusTooManyRequests,
		Message:    msg,
	}
}

// Internal returns a 500 error.
func Internal(msg string) *AppError {
	return &AppError{
		Code:       "internal_error",
		StatusCode: http.StatusInternalServerError,
		Message:    msg,
	}
}

// ServiceUnavailable returns a 503 error.
func ServiceUnavailable(msg string) *AppError {
	return &AppError{
		Code:       "service_unavailable",
		StatusCode: http.StatusServiceUnavailable,
		Message:    msg,
	}
}

// BadGateway returns a 502 error, typically when an upstream dependency fails.
func BadGateway(msg string) *AppError {
	return &AppError{
		Code:       "bad_gateway",
		StatusCode: http.StatusBadGateway,
		Message:    msg,
	}
}

// New builds an *AppError for an arbitrary status code, deriving a default
// machine-readable code from the status (see codeForStatus). Use it when the
// status is dynamic — e.g. proxying an upstream response — and the typed
// constructors above don't fit. The result can still be refined with
// WithKey/WithDetails before WriteJSON.
func New(status int, msg string) *AppError {
	return &AppError{
		Code:       codeForStatus(status),
		StatusCode: status,
		Message:    msg,
	}
}

// Write builds an AppError with New and writes it as a JSON response in a
// single call:
//
//	apierror.Write(w, http.StatusBadGateway, "upstream timed out")
func Write(w http.ResponseWriter, status int, msg string) {
	New(status, msg).WriteJSON(w)
}

// codeForStatus maps an HTTP status to the same machine-readable code emitted
// by the typed constructors, so a response is identical whether it originates
// from BadRequest("…") or New(400, "…"). Unmapped statuses fall back to a
// generic "error".
func codeForStatus(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "bad_request"
	case http.StatusUnauthorized:
		return "unauthorized"
	case http.StatusForbidden:
		return "forbidden"
	case http.StatusNotFound:
		return "not_found"
	case http.StatusConflict:
		return "conflict"
	case http.StatusUnprocessableEntity:
		return "validation_error"
	case http.StatusTooManyRequests:
		return "too_many_requests"
	case http.StatusInternalServerError:
		return "internal_error"
	case http.StatusBadGateway:
		return "bad_gateway"
	case http.StatusServiceUnavailable:
		return "service_unavailable"
	default:
		return "error"
	}
}

// WriteJSON writes the error as a JSON response to w.
//
// For 5xx responses the dev-facing Message and Details are not serialized — the
// client receives a generic status message under the same Code — so internal
// detail (e.g. apierror.Internal(err.Error())) cannot leak. 4xx responses are
// written as-is. The full error remains available for logging via Error().
func (e *AppError) WriteJSON(w http.ResponseWriter) {
	out := *e
	if e.StatusCode >= http.StatusInternalServerError {
		if msg := http.StatusText(e.StatusCode); msg != "" {
			out.Message = msg
		} else {
			out.Message = "internal server error"
		}
		out.Details = nil
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.StatusCode)
	json.NewEncoder(w).Encode(ErrorResponse{Error: out}) //nolint:errcheck
}

// ErrorWriter writes an *AppError as an HTTP response. Middleware that rejects
// requests (jwtauth, httpware.RequireTenant) accepts one, so an application
// chooses the shape of every error body it returns. JSONWriter (the default
// envelope) and ProblemWriter (RFC 9457) are ErrorWriters.
type ErrorWriter func(w http.ResponseWriter, r *http.Request, e *AppError)

// JSONWriter is the ErrorWriter for the default envelope: e.WriteJSON(w).
func JSONWriter(w http.ResponseWriter, _ *http.Request, e *AppError) { e.WriteJSON(w) }

// ProblemWriter is the ErrorWriter for RFC 9457 problem details: e.WriteProblem(w).
func ProblemWriter(w http.ResponseWriter, _ *http.Request, e *AppError) { e.WriteProblem(w) }

// Problem is an RFC 9457 problem details object, as WriteProblem writes it.
// Code, Key and Details are extension members carrying the AppError fields.
type Problem struct {
	Type    string `json:"type"`
	Title   string `json:"title"`
	Status  int    `json:"status"`
	Detail  string `json:"detail,omitempty"`
	Code    string `json:"code"`
	Key     string `json:"key,omitempty"`
	Details any    `json:"details,omitempty"`
}

// WriteProblem writes the error as RFC 9457 application/problem+json:
// "type" is "about:blank" and "title" the HTTP status text, as the RFC
// specifies for a problem with no type of its own; "detail" is the Message;
// "code", "key" and "details" carry the remaining fields as extension members.
// As with WriteJSON, a 5xx response omits the dev-facing Message and Details.
func (e *AppError) WriteProblem(w http.ResponseWriter) {
	p := Problem{
		Type:    "about:blank",
		Title:   http.StatusText(e.StatusCode),
		Status:  e.StatusCode,
		Detail:  e.Message,
		Code:    e.Code,
		Key:     e.Key,
		Details: e.Details,
	}
	if p.Title == "" {
		p.Title = "Error"
	}
	if e.StatusCode >= http.StatusInternalServerError {
		p.Detail, p.Details = "", nil
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(e.StatusCode)
	json.NewEncoder(w).Encode(p) //nolint:errcheck // the status line is already sent; nothing to do on a write error
}
