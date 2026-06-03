package apierror_test

import (
	"encoding/json"
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

// ExampleWrite demonstrates emitting an error for a dynamic status code in a
// single call — handy when proxying an upstream response whose status isn't
// known ahead of time. The code is derived from the status automatically.
func ExampleWrite() {
	rec := httptest.NewRecorder()
	apierror.Write(rec, http.StatusBadGateway, "upstream timed out")
	fmt.Println(rec.Code)

	var body struct {
		Error apierror.AppError `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	fmt.Println(body.Error.Code)
	// Output:
	// 502
	// bad_gateway
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
