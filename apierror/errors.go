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
	Message    string `json:"message"`
	StatusCode int    `json:"-"`
	Details    any    `json:"details,omitempty"`
}

func (e *AppError) Error() string { return e.Message }

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

// WriteJSON writes the error as a JSON response to w.
func (e *AppError) WriteJSON(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.StatusCode)
	json.NewEncoder(w).Encode(ErrorResponse{Error: *e}) //nolint:errcheck
}
