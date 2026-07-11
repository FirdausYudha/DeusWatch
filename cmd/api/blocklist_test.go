package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeBlocks struct{ ips []string }

func (f fakeBlocks) ActiveBlocks(context.Context) ([]string, error) { return f.ips, nil }

func TestBlocklistFeedHandler(t *testing.T) {
	bl := fakeBlocks{ips: []string{"5.6.7.8", "1.2.3.4"}}

	// Disabled when no token: 404.
	rec := httptest.NewRecorder()
	blocklistFeedHandler(bl, "")(rec, httptest.NewRequest("GET", "/api/blocklist", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("no token should 404, got %d", rec.Code)
	}

	h := blocklistFeedHandler(bl, "secret")

	// Wrong token: 403.
	rec = httptest.NewRecorder()
	h(rec, httptest.NewRequest("GET", "/api/blocklist?token=nope", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("wrong token should 403, got %d", rec.Code)
	}

	// Correct token, plaintext (sorted, one IP per line).
	rec = httptest.NewRecorder()
	h(rec, httptest.NewRequest("GET", "/api/blocklist?token=secret", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("valid token should 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "1.2.3.4\n") || !strings.Contains(body, "5.6.7.8\n") {
		t.Fatalf("plaintext feed missing IPs:\n%s", body)
	}
	if strings.Index(body, "1.2.3.4") > strings.Index(body, "5.6.7.8") {
		t.Fatal("IPs should be sorted")
	}

	// Correct token, JSON.
	rec = httptest.NewRecorder()
	h(rec, httptest.NewRequest("GET", "/api/blocklist?token=secret&format=json", nil))
	var out struct {
		Count int      `json:"count"`
		IPs   []string `json:"ips"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("json decode: %v", err)
	}
	if out.Count != 2 || len(out.IPs) != 2 {
		t.Fatalf("json feed wrong: %+v", out)
	}
}
