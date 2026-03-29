// Package pagination provides HTTP query parameter parsing and response
// helpers for cursor-free, page-number-based pagination.
package pagination

import (
	"net/http"
	"strconv"
)

// Params holds parsed pagination parameters.
type Params struct {
	Page    int `json:"page"`
	PerPage int `json:"perPage"`
	Offset  int `json:"-"`
}

const (
	DefaultPerPage = 20
	MaxPerPage     = 100
)

// Parse extracts page and per_page from the request query string, applying
// defaults and clamping per_page to MaxPerPage.
func Parse(r *http.Request) Params {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))

	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = DefaultPerPage
	}
	if perPage > MaxPerPage {
		perPage = MaxPerPage
	}

	return Params{
		Page:    page,
		PerPage: perPage,
		Offset:  (page - 1) * perPage,
	}
}

// PagedResponse wraps a list result with pagination metadata.
type PagedResponse struct {
	Data       any   `json:"data"`
	Page       int   `json:"page"`
	PerPage    int   `json:"perPage"`
	TotalItems int64 `json:"totalItems"`
	TotalPages int   `json:"totalPages"`
}

// NewPagedResponse builds a PagedResponse from data, params, and total item count.
func NewPagedResponse(data any, params Params, totalItems int64) PagedResponse {
	totalPages := int(totalItems) / params.PerPage
	if int(totalItems)%params.PerPage > 0 {
		totalPages++
	}
	return PagedResponse{
		Data:       data,
		Page:       params.Page,
		PerPage:    params.PerPage,
		TotalItems: totalItems,
		TotalPages: totalPages,
	}
}
