package rdap

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

func loadFixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("../../testdata/rdap/com-example.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	return b
}

func TestMalformedResponseError_ErrorAndUnwrap(t *testing.T) {
	wrapped := errors.New("unexpected EOF")
	e := &MalformedResponseError{
		URL:         "https://rdap.example.com/domain/example.com",
		StatusCode:  http.StatusOK,
		ContentType: "text/html",
		Snippet:     "<html>oops</html>",
		Err:         wrapped,
	}

	got := e.Error()
	for _, want := range []string{e.URL, "200", e.ContentType, e.Snippet} {
		if !strings.Contains(got, want) {
			t.Errorf("Error() = %q, want it to contain %q", got, want)
		}
	}

	if !errors.Is(e, wrapped) {
		t.Errorf("errors.Is(e, wrapped) = false, want true (Unwrap should expose Err)")
	}
}

func TestClientDomain_HappyPath(t *testing.T) {
	fixture := loadFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/domain/EXAMPLE.COM" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Accept") != "application/rdap+json" {
			t.Errorf("missing Accept header, got %q", r.Header.Get("Accept"))
		}
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	c := &Client{}
	result, err := c.Domain(context.Background(), srv.URL, "EXAMPLE.COM")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Domain == nil {
		t.Fatal("Domain is nil")
	}
	if result.Domain.LDHName != "EXAMPLE.COM" {
		t.Errorf("LDHName = %q, want EXAMPLE.COM", result.Domain.LDHName)
	}
	if len(result.Domain.Status) != 3 {
		t.Errorf("Status = %v, want 3 entries", result.Domain.Status)
	}
	if len(result.Domain.Nameservers) != 2 {
		t.Errorf("Nameservers = %v, want 2 entries", result.Domain.Nameservers)
	}
	created, ok := result.Domain.Created()
	if !ok || created.Raw != "1995-08-14T04:00:00Z" {
		t.Errorf("Created() = %v, %v", created, ok)
	}
	if !result.MediaTypeConformant {
		t.Errorf("MediaTypeConformant = false, want true")
	}
	if len(result.Raw) == 0 {
		t.Errorf("Raw body not retained")
	}
}

func TestClientDomain_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errorCode":404,"title":"Not Found"}`))
	}))
	defer srv.Close()

	c := &Client{}
	result, err := c.Domain(context.Background(), srv.URL, "nonexistent-example.com")
	if !errors.Is(err, ErrDomainNotFound) {
		t.Fatalf("error = %v, want ErrDomainNotFound", err)
	}
	if result == nil || len(result.Raw) == 0 {
		t.Errorf("Raw body should still be retained on 404")
	}
}

func TestClientDomain_RateLimitedThenSucceeds(t *testing.T) {
	fixture := loadFixture(t)
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	c := &Client{}
	result, err := c.Domain(context.Background(), srv.URL, "EXAMPLE.COM")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if attempts != 2 {
		t.Errorf("attempts = %d, want 2 (one retry)", attempts)
	}
	if result.Domain == nil {
		t.Fatal("Domain is nil")
	}
}

func TestClientDomain_RateLimitedGivesUp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c := &Client{}
	_, err := c.Domain(context.Background(), srv.URL, "EXAMPLE.COM")
	if err == nil {
		t.Fatal("expected an error after single retry still returns 429")
	}
	var malformed *MalformedResponseError
	if !errors.As(err, &malformed) {
		t.Fatalf("error = %v (%T), want *MalformedResponseError", err, err)
	}
	if malformed.StatusCode != http.StatusTooManyRequests {
		t.Errorf("StatusCode = %d, want 429", malformed.StatusCode)
	}
}

func TestClientDomain_NonJSONBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><body>upstream error</body></html>`))
	}))
	defer srv.Close()

	c := &Client{}
	_, err := c.Domain(context.Background(), srv.URL, "EXAMPLE.COM")
	var malformed *MalformedResponseError
	if !errors.As(err, &malformed) {
		t.Fatalf("error = %v (%T), want *MalformedResponseError", err, err)
	}
	if !strings.Contains(malformed.Snippet, "upstream error") {
		t.Errorf("Snippet = %q, want to contain body text", malformed.Snippet)
	}
}

func TestClientDomain_NonDomainObjectClass(t *testing.T) {
	body := `{"objectClassName":"nameserver","ldhName":"NS1.EXAMPLE.COM"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	c := &Client{}
	result, err := c.Domain(context.Background(), srv.URL, "EXAMPLE.COM")
	var malformed *MalformedResponseError
	if !errors.As(err, &malformed) {
		t.Fatalf("error = %v (%T), want *MalformedResponseError", err, err)
	}
	if result == nil || len(result.Raw) == 0 {
		t.Errorf("Raw body should still be retained when objectClassName is not domain")
	}
}

func TestClientDomain_MalformedStatusField(t *testing.T) {
	body := `{"objectClassName":"domain","ldhName":"EXAMPLE.COM","status":42}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	c := &Client{}
	result, err := c.Domain(context.Background(), srv.URL, "EXAMPLE.COM")
	if err != nil {
		t.Fatalf("unexpected error (status field should degrade gracefully): %v", err)
	}
	if len(result.Domain.Status) != 0 {
		t.Errorf("Status = %v, want empty (malformed field should degrade, not error)", result.Domain.Status)
	}
}

func TestClientDomain_UnparseableEventDate(t *testing.T) {
	body := `{"objectClassName":"domain","ldhName":"EXAMPLE.COM","events":[{"eventAction":"registration","eventDate":"not-a-date"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	c := &Client{}
	result, err := c.Domain(context.Background(), srv.URL, "EXAMPLE.COM")
	if err != nil {
		t.Fatalf("unexpected error (bad date should degrade gracefully): %v", err)
	}
	created, ok := result.Domain.Created()
	if !ok {
		t.Fatal("Created() event should still be present")
	}
	if created.Parsed {
		t.Errorf("Parsed = true, want false for unparseable date")
	}
	if created.Raw != "not-a-date" {
		t.Errorf("Raw = %q, want %q", created.Raw, "not-a-date")
	}
}

func TestClientDomain_RetriesOn429(t *testing.T) {
	fixture, err := os.ReadFile("../../testdata/rdap/org-thick-example.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}

	var requestCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if requestCount == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	c := &Client{}
	result, err := c.Domain(context.Background(), srv.URL, "EXAMPLE.ORG")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if requestCount != 2 {
		t.Fatalf("requestCount = %d, want 2 (one 429, one successful retry)", requestCount)
	}
	if result.Domain == nil {
		t.Fatal("Domain is nil")
	}
	if result.Domain.LDHName != "EXAMPLE.ORG" {
		t.Errorf("LDHName = %q, want EXAMPLE.ORG", result.Domain.LDHName)
	}
}

func TestClient_IP(t *testing.T) {
	const body = `{
	  "objectClassName": "ip network",
	  "handle": "NET-8-8-8-0-2",
	  "startAddress": "8.8.8.0",
	  "endAddress": "8.8.8.255",
	  "ipVersion": "v4",
	  "name": "GOGL",
	  "type": "DIRECT ALLOCATION",
	  "parentHandle": "NET-8-0-0-0-0",
	  "status": ["active"],
	  "cidr0_cidrs": [{"v4prefix": "8.8.8.0", "length": 24}],
	  "events": [{"eventAction": "registration", "eventDate": "2023-12-28T17:24:33-05:00"}],
	  "port43": "whois.arin.net"
	}`
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	c := &Client{}
	res, err := c.IP(context.Background(), srv.URL, netip.MustParseAddr("8.8.8.8"))
	if err != nil {
		t.Fatalf("IP: %v", err)
	}
	if gotPath != "/ip/8.8.8.8" {
		t.Errorf("request path = %q, want /ip/8.8.8.8", gotPath)
	}
	if res.IPNetwork == nil {
		t.Fatal("Result.IPNetwork = nil, want the parsed object")
	}
	if res.IPNetwork.Handle != "NET-8-8-8-0-2" {
		t.Errorf("Handle = %q, want NET-8-8-8-0-2", res.IPNetwork.Handle)
	}
	if len(res.IPNetwork.CIDR0CIDRs) != 1 || res.IPNetwork.CIDR0CIDRs[0].Length != 24 {
		t.Errorf("CIDR0CIDRs = %+v, want one /24 entry", res.IPNetwork.CIDR0CIDRs)
	}
	if res.IPNetwork.Port43 != "whois.arin.net" {
		t.Errorf("Port43 = %q, want whois.arin.net", res.IPNetwork.Port43)
	}
}

func TestClient_IP_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := &Client{}
	_, err := c.IP(context.Background(), srv.URL, netip.MustParseAddr("8.8.8.8"))
	if !errors.Is(err, ErrDomainNotFound) {
		t.Errorf("err = %v, want ErrDomainNotFound", err)
	}
}

func TestClient_IP_RetriesOn429(t *testing.T) {
	const body = `{
	  "objectClassName": "ip network",
	  "handle": "NET-8-8-8-0-2",
	  "startAddress": "8.8.8.0",
	  "endAddress": "8.8.8.255",
	  "ipVersion": "v4",
	  "name": "GOGL"
	}`
	var requestCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if requestCount == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	c := &Client{}
	res, err := c.IP(context.Background(), srv.URL, netip.MustParseAddr("8.8.8.8"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if requestCount != 2 {
		t.Fatalf("requestCount = %d, want 2 (one 429, one successful retry)", requestCount)
	}
	if res.IPNetwork == nil {
		t.Fatal("IPNetwork is nil")
	}
	if res.IPNetwork.Handle != "NET-8-8-8-0-2" {
		t.Errorf("Handle = %q, want NET-8-8-8-0-2", res.IPNetwork.Handle)
	}
}

func TestClient_IP_ErrorStatusSurfacesTitle(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"errorCode":500,"title":"Internal Server Error"}`))
	}))
	defer srv.Close()

	c := &Client{}
	res, err := c.IP(context.Background(), srv.URL, netip.MustParseAddr("8.8.8.8"))
	if err == nil {
		t.Fatal("expected an error for a 500 status")
	}
	if !strings.Contains(err.Error(), "Internal Server Error") {
		t.Errorf("err = %q, want it to contain the server's title", err.Error())
	}
	var malformed *MalformedResponseError
	if errors.As(err, &malformed) {
		t.Errorf("err = %v, want a plain error surfacing the title, not *MalformedResponseError", err)
	}
	if res == nil || res.StatusCode != http.StatusInternalServerError {
		t.Errorf("Result.StatusCode not populated as 500: %+v", res)
	}
}

func TestClient_IP_MalformedBody(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
		wantErrSet  bool // whether MalformedResponseError.Err should be non-nil
	}{
		{
			name:        "non-JSON body",
			contentType: "text/html",
			body:        "<html><body>upstream error</body></html>",
		},
		{
			name:        "malformed JSON structure",
			contentType: "application/rdap+json",
			body:        `{"objectClassName":"ip network","cidr0_cidrs":"not-an-array"}`,
			wantErrSet:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", tt.contentType)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer srv.Close()

			c := &Client{}
			res, err := c.IP(context.Background(), srv.URL, netip.MustParseAddr("8.8.8.8"))
			var malformed *MalformedResponseError
			if !errors.As(err, &malformed) {
				t.Fatalf("error = %v (%T), want *MalformedResponseError", err, err)
			}
			if malformed.URL == "" || malformed.StatusCode == 0 || malformed.Snippet == "" {
				t.Errorf("MalformedResponseError fields not populated: %+v", malformed)
			}
			if tt.wantErrSet && malformed.Err == nil {
				t.Errorf("Err = nil, want the underlying json.Unmarshal error to be wrapped")
			}
			if res == nil || res.IPNetwork != nil {
				t.Errorf("IPNetwork should remain nil on malformed body, got %+v", res)
			}
		})
	}
}

func TestClient_IP_WrongObjectClassName(t *testing.T) {
	body := `{"objectClassName":"nameserver","handle":"NS1.EXAMPLE.COM"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	c := &Client{}
	res, err := c.IP(context.Background(), srv.URL, netip.MustParseAddr("8.8.8.8"))
	var malformed *MalformedResponseError
	if !errors.As(err, &malformed) {
		t.Fatalf("error = %v (%T), want *MalformedResponseError", err, err)
	}
	if res == nil {
		t.Fatal("Result should still be returned when objectClassName mismatches")
	}
	if res.IPNetwork != nil {
		t.Errorf("IPNetwork = %+v, want nil when objectClassName is not \"ip network\"", res.IPNetwork)
	}
}

func TestClient_ASN(t *testing.T) {
	const body = `{
	  "objectClassName": "autnum",
	  "handle": "AS15169",
	  "startAutnum": 15169,
	  "endAutnum": 15169,
	  "name": "GOOGLE",
	  "status": ["active"],
	  "events": [{"eventAction": "registration", "eventDate": "2000-03-30T00:00:00-05:00"}],
	  "port43": "whois.arin.net"
	}`
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	c := &Client{}
	res, err := c.ASN(context.Background(), srv.URL, 15169)
	if err != nil {
		t.Fatalf("ASN: %v", err)
	}
	if gotPath != "/autnum/15169" {
		t.Errorf("request path = %q, want /autnum/15169", gotPath)
	}
	if res.ASN == nil {
		t.Fatal("Result.ASN = nil, want the parsed object")
	}
	if res.ASN.Handle != "AS15169" || res.ASN.StartAutnum != 15169 || res.ASN.Name != "GOOGLE" {
		t.Errorf("parsed = %+v, want handle AS15169 / startAutnum 15169 / name GOOGLE", res.ASN)
	}
}

// TestClient_ASN_RealARINGolden decodes a real RDAP autnum document
// (captured live from https://rdap.arin.net/registry/autnum/15169) rather
// than the hand-written inline JSON every other ASN client test in this
// file uses. Every other ASN-path test -- here and in
// internal/collect/adapt_asn_test.go -- either hand-writes a minimal JSON
// body or constructs rdap.ASNResponse/Entity/VCardArray structs directly,
// so nothing before this test hermetically proved a real RIR's autnum
// document actually decodes the way the entity/vCard extraction code
// assumes; that was validated only by live runs against actual RIRs. The
// domain path already has this coverage via testdata/rdap/*.json; this is
// the ASN path's counterpart.
func TestClient_ASN_RealARINGolden(t *testing.T) {
	body, err := os.ReadFile("../../testdata/rdap/arin-as15169.json")
	if err != nil {
		t.Fatalf("reading golden: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	c := &Client{}
	res, err := c.ASN(context.Background(), srv.URL, 15169)
	if err != nil {
		t.Fatalf("ASN: %v", err)
	}
	if res.ASN == nil {
		t.Fatal("Result.ASN = nil, want the parsed object")
	}
	a := res.ASN

	if a.Handle != "AS15169" {
		t.Errorf("Handle = %q, want AS15169", a.Handle)
	}
	if a.Name != "GOOGLE" {
		t.Errorf("Name = %q, want GOOGLE", a.Name)
	}
	if a.StartAutnum != 15169 || a.EndAutnum != 15169 {
		t.Errorf("StartAutnum/EndAutnum = %d/%d, want 15169/15169", a.StartAutnum, a.EndAutnum)
	}
	if len(a.Status) != 1 || a.Status[0] != "active" {
		t.Errorf("Status = %v, want [active]", a.Status)
	}

	reg, ok := a.RegistrantEntity()
	if !ok {
		t.Fatal("RegistrantEntity() ok = false, want true")
	}
	if reg.VCardArray.FullName != "Google LLC" {
		t.Errorf("RegistrantEntity().VCardArray.FullName = %q, want Google LLC", reg.VCardArray.FullName)
	}

	// ARIN nests its abuse-role entity inside the top-level registrant
	// entity's own "entities" array rather than listing it at the top
	// level -- unlike the abuse-role entity in the collect package's
	// hand-built arinLikeASN test fixture, which (like every other ASN
	// adapter test) places it at the top level for convenience.
	// AbuseEntity's entityByRole deliberately only scans top-level
	// entities (mirrors DomainResponse's M3-era "nested traversal is a
	// later milestone" scope), so it must NOT find ARIN's real, nested
	// abuse entity here. This golden is what proves that gap is real on
	// live data, not just a theoretical corner the hand-built fixtures
	// never exercised.
	if _, ok := a.AbuseEntity(); ok {
		t.Error("AbuseEntity() ok = true, want false (ARIN's abuse entity is nested under registrant, not top-level)")
	}

	registered, ok := a.Registered()
	if !ok || !registered.Parsed {
		t.Fatalf("Registered() = %+v, %v, want a parsed event", registered, ok)
	}
	if registered.Raw != "2000-03-30T00:00:00-05:00" {
		t.Errorf("Registered().Raw = %q, want 2000-03-30T00:00:00-05:00", registered.Raw)
	}

	updated, ok := a.Updated()
	if !ok || !updated.Parsed {
		t.Fatalf("Updated() = %+v, %v, want a parsed event", updated, ok)
	}
	if updated.Raw != "2012-02-24T09:44:34-05:00" {
		t.Errorf("Updated().Raw = %q, want 2012-02-24T09:44:34-05:00", updated.Raw)
	}
}

func TestClient_ASN_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := &Client{}
	_, err := c.ASN(context.Background(), srv.URL, 15169)
	if !errors.Is(err, ErrDomainNotFound) {
		t.Errorf("err = %v, want ErrDomainNotFound", err)
	}
}

func TestClient_ASN_RetriesOn429(t *testing.T) {
	const body = `{
	  "objectClassName": "autnum",
	  "handle": "AS15169",
	  "startAutnum": 15169,
	  "endAutnum": 15169,
	  "name": "GOOGLE"
	}`
	var requestCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if requestCount == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	c := &Client{}
	res, err := c.ASN(context.Background(), srv.URL, 15169)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if requestCount != 2 {
		t.Fatalf("requestCount = %d, want 2 (one 429, one successful retry)", requestCount)
	}
	if res.ASN == nil {
		t.Fatal("ASN is nil")
	}
	if res.ASN.Handle != "AS15169" {
		t.Errorf("Handle = %q, want AS15169", res.ASN.Handle)
	}
}

func TestClient_ASN_ErrorStatusSurfacesTitle(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"errorCode":500,"title":"Internal Server Error"}`))
	}))
	defer srv.Close()

	c := &Client{}
	res, err := c.ASN(context.Background(), srv.URL, 15169)
	if err == nil {
		t.Fatal("expected an error for a 500 status")
	}
	if !strings.Contains(err.Error(), "Internal Server Error") {
		t.Errorf("err = %q, want it to contain the server's title", err.Error())
	}
	var malformed *MalformedResponseError
	if errors.As(err, &malformed) {
		t.Errorf("err = %v, want a plain error surfacing the title, not *MalformedResponseError", err)
	}
	if res == nil || res.StatusCode != http.StatusInternalServerError {
		t.Errorf("Result.StatusCode not populated as 500: %+v", res)
	}
}

func TestClient_ASN_MalformedBody(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
		wantErrSet  bool // whether MalformedResponseError.Err should be non-nil
	}{
		{
			name:        "non-JSON body",
			contentType: "text/html",
			body:        "<html><body>upstream error</body></html>",
		},
		{
			name:        "malformed JSON structure",
			contentType: "application/rdap+json",
			body:        `{"objectClassName":"autnum","startAutnum":"not-a-number"}`,
			wantErrSet:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", tt.contentType)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer srv.Close()

			c := &Client{}
			res, err := c.ASN(context.Background(), srv.URL, 15169)
			var malformed *MalformedResponseError
			if !errors.As(err, &malformed) {
				t.Fatalf("error = %v (%T), want *MalformedResponseError", err, err)
			}
			if malformed.URL == "" || malformed.StatusCode == 0 || malformed.Snippet == "" {
				t.Errorf("MalformedResponseError fields not populated: %+v", malformed)
			}
			if tt.wantErrSet && malformed.Err == nil {
				t.Errorf("Err = nil, want the underlying json.Unmarshal error to be wrapped")
			}
			if res == nil || res.ASN != nil {
				t.Errorf("ASN should remain nil on malformed body, got %+v", res)
			}
		})
	}
}

func TestClient_ASN_WrongObjectClassName(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write([]byte(`{"objectClassName":"ip network","handle":"NET-1"}`))
	}))
	defer srv.Close()

	c := &Client{}
	res, err := c.ASN(context.Background(), srv.URL, 15169)
	var malformed *MalformedResponseError
	if !errors.As(err, &malformed) {
		t.Fatalf("error = %v (%T), want *MalformedResponseError", err, err)
	}
	if res == nil {
		t.Fatal("Result should still be returned when objectClassName mismatches")
	}
	if res.ASN != nil {
		t.Errorf("ASN = %+v, want nil when objectClassName is not \"autnum\"", res.ASN)
	}
}

func TestRetryAfter(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   time.Duration
	}{
		{"absent header defaults to 1s", "", time.Second},
		{"positive seconds", "5", 5 * time.Second},
		{"zero seconds", "0", 0},
		{
			// The HTTP-date branch explicitly discards a non-positive
			// delay and falls back to the polite 1s default (see the
			// `if d > 0` guard a few lines below in retryAfter) -- the
			// delay-seconds branch had no equivalent guard, so a
			// negative value passed straight through as a negative
			// time.Duration, making the "one polite retry" fire
			// essentially immediately instead of waiting at all.
			"negative seconds is clamped like the date form is",
			"-5",
			time.Second,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := http.Header{}
			if tt.header != "" {
				h.Set("Retry-After", tt.header)
			}
			got := retryAfter(h)
			if got != tt.want {
				t.Errorf("retryAfter(Retry-After=%q) = %v, want %v", tt.header, got, tt.want)
			}
		})
	}
}
