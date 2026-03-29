package pagination_test

import (
	"fmt"
	"net/http/httptest"

	"github.com/ovander/backendkit/pagination"
)

// ExampleParse demonstrates parsing page and per_page query parameters with
// default and maximum clamping applied automatically.
func ExampleParse() {
	req := httptest.NewRequest("GET", "/users?page=3&per_page=50", nil)
	p := pagination.Parse(req)
	fmt.Println(p.Page, p.PerPage)
	// Output:
	// 3 50
}

// ExampleParse_defaults shows the default values used when no query params
// are provided.
func ExampleParse_defaults() {
	req := httptest.NewRequest("GET", "/users", nil)
	p := pagination.Parse(req)
	fmt.Println(p.Page, p.PerPage)
	// Output:
	// 1 20
}

// ExampleNewPagedResponse demonstrates wrapping a slice result with pagination
// metadata for a JSON API response.
func ExampleNewPagedResponse() {
	items := []string{"alpha", "beta", "gamma"}
	params := pagination.Params{Page: 1, PerPage: 20}
	resp := pagination.NewPagedResponse(items, params, 3)

	fmt.Println(resp.TotalItems)
	fmt.Println(resp.Page)
	fmt.Println(resp.TotalPages)
	// Output:
	// 3
	// 1
	// 1
}
