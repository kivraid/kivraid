package web

import (
	"html/template"
	"net/http"
	"strconv"
)

// pager is the page state shared by paginated admin lists. Callers count the
// rows, call pageWindow for the LIMIT/OFFSET, then fill the pager once the
// page is loaded.
type pager struct {
	Page, Pages int
	Total       int64
	Start, End  int64 // 1-based range shown, 0/0 when empty
	Prev, Next  int   // 0 when there is no such page
	// Param is the query parameter carrying the page number; QS is the rest
	// of the query string (encoded filters) to keep on page links.
	Param string
	QS    template.URL // already escaped by url.Values.Encode
}

// pageWindow reads the page number from the request (clamped to the
// existing pages) and returns it with the LIMIT/OFFSET to query.
func pageWindow(r *http.Request, param string, total int64, size int32) (page, pages int, limit, offset int32) {
	pages = int((total + int64(size) - 1) / int64(size))
	if pages < 1 {
		pages = 1
	}
	page = 1
	if p, err := strconv.Atoi(r.URL.Query().Get(param)); err == nil && p > 1 {
		page = p
	}
	if page > pages {
		page = pages
	}
	return page, pages, size, int32(page-1) * size
}

func newPager(param string, qs template.URL, page, pages int, total int64, size int32, shown int) pager {
	p := pager{Page: page, Pages: pages, Total: total, Param: param, QS: qs}
	if total > 0 {
		p.Start = int64(page-1)*int64(size) + 1
		p.End = int64(page-1)*int64(size) + int64(shown)
	}
	if page > 1 {
		p.Prev = page - 1
	}
	if page < pages {
		p.Next = page + 1
	}
	return p
}
