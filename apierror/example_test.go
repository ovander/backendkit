package apierror_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/ovander/backendkit/apierror"
)

// ExampleNotFound shows how to return a structured 404 from a handler.
func ExampleNotFound() {
	rec := httptest.NewRecorder()
	apierror.NotFound("workspace", "ws-999").WriteJSON(rec)
	fmt.Println(rec.Code)
	fmt.Println(rec.Header().Get("Content-Type"))
	// Output:
	// 404
	// application/json
}

// ExampleUnauthorized shows a 401 response for a missing or invalid token.
func ExampleUnauthorized() {
	err := apierror.Unauthorized("token expired")
	fmt.Println(err.StatusCode)
	fmt.Println(err.Code)
	// Output:
	// 401
	// unauthorized
}

// ExampleValidationError shows attaching field-level detail to a 422 error.
func ExampleValidationError() {
	rec := httptest.NewRecorder()
	apierror.ValidationError("invalid input", map[string]string{
		"email": "must be a valid email address",
		"name":  "required",
	}).WriteJSON(rec)
	fmt.Println(rec.Code)
	// Output:
	// 422
}

// ExampleAppError_WriteJSON demonstrates writing any AppError to an
// http.ResponseWriter with the correct status code and JSON content-type.
func ExampleAppError_WriteJSON() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apierror.Forbidden("insufficient permissions").WriteJSON(w)
	})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin", nil))
	fmt.Println(rec.Code)
	// Output:
	// 403
}
