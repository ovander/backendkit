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
	Code       string `json:"code"`
	Key        string `json:"key,omitempty"` // i18n key — frontend translates this
	Message    string `json:"message"`       // English dev-facing message (logs only)
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
func (e *AppError) WriteJSON(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.StatusCode)
	json.NewEncoder(w).Encode(ErrorResponse{Error: *e}) //nolint:errcheck
}
