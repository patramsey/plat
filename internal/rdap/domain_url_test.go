package rdap

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestDomainURL_HappyPath(t *testing.T) {
	fixture, err := os.ReadFile("../../testdata/rdap/com-example.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	c := &Client{}
	result, err := c.DomainURL(context.Background(), srv.URL+"/rdap/domain/EXAMPLE.COM")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Domain == nil || result.Domain.LDHName != "EXAMPLE.COM" {
		t.Fatalf("Domain = %+v", result.Domain)
	}
}

func TestDomainURL_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errorCode":404,"title":"Not Found"}`))
	}))
	defer srv.Close()

	c := &Client{}
	_, err := c.DomainURL(context.Background(), srv.URL+"/rdap/domain/nonexistent.example.com")
	if err == nil {
		t.Fatal("expected an error")
	}
}

func TestDomainURL_RejectsBadScheme(t *testing.T) {
	tests := []string{
		"javascript:alert(1)",
		"file:///etc/passwd",
		"ftp://example.com/domain/x",
		"not-a-url-at-all",
		"",
	}
	c := &Client{}
	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			_, err := c.DomainURL(context.Background(), raw)
			if err == nil {
				t.Errorf("DomainURL(%q) expected an error, got nil", raw)
			}
		})
	}
}
