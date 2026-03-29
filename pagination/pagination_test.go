package pagination_test

import (
	"net/http/httptest"
	"testing"

	"github.com/ovander/backendkit/pagination"
)

func TestParse(t *testing.T) {
	tests := []struct {
		query      string
		wantPage   int
		wantPer    int
		wantOffset int
	}{
		{"", 1, 20, 0},
		{"page=0&per_page=0", 1, 20, 0},
		{"page=2&per_page=10", 2, 10, 10},
		{"page=3&per_page=5", 3, 5, 10},
		{"per_page=150", 1, 100, 0},  // clamped to MaxPerPage
		{"page=-1", 1, 20, 0},        // negative → default
	}

	for _, tt := range tests {
		r := httptest.NewRequest("GET", "/?"+tt.query, nil)
		p := pagination.Parse(r)

		if p.Page != tt.wantPage {
			t.Errorf("query=%q: Page = %d, want %d", tt.query, p.Page, tt.wantPage)
		}
		if p.PerPage != tt.wantPer {
			t.Errorf("query=%q: PerPage = %d, want %d", tt.query, p.PerPage, tt.wantPer)
		}
		if p.Offset != tt.wantOffset {
			t.Errorf("query=%q: Offset = %d, want %d", tt.query, p.Offset, tt.wantOffset)
		}
	}
}

func TestNewPagedResponse(t *testing.T) {
	params := pagination.Params{Page: 1, PerPage: 10, Offset: 0}

	tests := []struct {
		total      int64
		wantPages  int
	}{
		{0, 0},
		{1, 1},
		{10, 1},  // exactly one page
		{11, 2},  // one item on second page
		{20, 2},
		{21, 3},
	}

	for _, tt := range tests {
		pr := pagination.NewPagedResponse([]string{}, params, tt.total)
		if pr.TotalPages != tt.wantPages {
			t.Errorf("total=%d: TotalPages = %d, want %d", tt.total, pr.TotalPages, tt.wantPages)
		}
		if pr.TotalItems != tt.total {
			t.Errorf("TotalItems = %d, want %d", pr.TotalItems, tt.total)
		}
	}
}
