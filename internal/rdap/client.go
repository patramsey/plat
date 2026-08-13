package rdap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ErrDomainNotFound is returned when the RDAP server responds 404 for a
// domain query — the standard RDAP not-found signal, regardless of what
// (if anything) the response body contains.
var ErrDomainNotFound = errors.New("rdap: domain not found")

// MalformedResponseError is returned when a server's response can't be
// interpreted as RDAP JSON — an HTML error page, plaintext, or truncated
// body, for example — so a conformance surprise is debuggable rather than
// surfacing as a bare json.SyntaxError or a panic.
type MalformedResponseError struct {
	URL         string
	StatusCode  int
	ContentType string
	Snippet     string
	Err         error
}

func (e *MalformedResponseError) Error() string {
	return fmt.Sprintf("rdap: malformed response from %s (status %d, content-type %q): %s",
		e.URL, e.StatusCode, e.ContentType, e.Snippet)
}

func (e *MalformedResponseError) Unwrap() error { return e.Err }

// Result wraps a parsed DomainResponse together with the raw bytes and
// transport metadata needed to debug a conformance surprise. It is
// deliberately lighter than the full multi-source provenance model
// (that's a later milestone) — just enough to not lose information.
type Result struct {
	Domain              *DomainResponse
	IPNetwork           *IPNetworkResponse
	ASN                 *ASNResponse
	Raw                 []byte
	StatusCode          int
	ContentType         string
	MediaTypeConformant bool
}

// rdapObject is satisfied by every RDAP response type this package
// decodes. It exists because Go generics cannot read struct fields
// through a type parameter -- only methods -- so fetchAt reaches each
// response's objectClassName through this instead of the field directly.
type rdapObject interface {
	objectClass() string
}

func (d DomainResponse) objectClass() string    { return d.ObjectClassName }
func (n IPNetworkResponse) objectClass() string { return n.ObjectClassName }
func (a ASNResponse) objectClass() string       { return a.ObjectClassName }

// Client is a minimal RDAP client for a single registry domain query.
type Client struct {
	HTTP      *http.Client
	Timeout   time.Duration
	MaxBody   int64
	UserAgent string
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

func (c *Client) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return 5 * time.Second
}

func (c *Client) maxBody() int64 {
	if c.MaxBody > 0 {
		return c.MaxBody
	}
	return 5 << 20
}

func (c *Client) userAgent() string {
	if c.UserAgent != "" {
		return c.UserAgent
	}
	return "plat/0.1"
}

type rawResponse struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

func (c *Client) do(ctx context.Context, reqURL string) (*rawResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("rdap: building request: %w", err)
	}
	req.Header.Set("Accept", "application/rdap+json")
	req.Header.Set("User-Agent", c.userAgent())

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("rdap: requesting %s: %w", reqURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBody()))
	if err != nil {
		return nil, fmt.Errorf("rdap: reading response body from %s: %w", reqURL, err)
	}

	return &rawResponse{StatusCode: resp.StatusCode, Header: resp.Header, Body: body}, nil
}

func retryAfter(h http.Header) time.Duration {
	v := h.Get("Retry-After")
	if v == "" {
		return time.Second
	}
	if secs, err := strconv.Atoi(v); err == nil {
		// Only a genuinely negative value is invalid and falls back to
		// the polite default -- 0 is a legitimate "retry immediately"
		// value some servers (and this package's own tests) send, unlike
		// the HTTP-date branch below where a past/non-positive delay has
		// no meaningful non-zero duration to return.
		if secs < 0 {
			return time.Second
		}
		return time.Duration(secs) * time.Second
	}
	if when, err := http.ParseTime(v); err == nil {
		if d := time.Until(when); d > 0 {
			return d
		}
	}
	return time.Second
}

// rdapError is the minimal RFC 9083 error-response shape.
type rdapError struct {
	ErrorCode   int      `json:"errorCode"`
	Title       string   `json:"title"`
	Description []string `json:"description"`
}

func snippet(body []byte) string {
	const max = 512
	s := string(body)
	if len(s) > max {
		s = s[:max]
	}
	var b strings.Builder
	for _, r := range s {
		if r == '\n' || r == '\t' || (r >= 0x20 && r != 0x7f) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Domain queries baseURL for the given punycode domain name and returns
// the parsed result. baseURL is the RDAP service base (typically resolved
// from IANA bootstrap); punycode is the ASCII domain name to look up.
func (c *Client) Domain(ctx context.Context, baseURL, punycode string) (*Result, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()

	reqURL := strings.TrimRight(baseURL, "/") + "/domain/" + url.PathEscape(punycode)
	return c.domainAt(ctx, reqURL)
}

// DomainURL fetches and parses the RDAP domain object at rawURL directly
// — used to follow a registry response's registrar "related" link, whose
// href is already a complete domain-object URL, not a base to append
// "/domain/{name}" to. rawURL must be a valid http(s) URL; anything else
// (a bad scheme, an unparseable string) is rejected before any network
// call is attempted.
func (c *Client) DomainURL(ctx context.Context, rawURL string) (*Result, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("rdap: invalid registrar URL %q: %w", rawURL, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("rdap: unsupported URL scheme %q in %q", parsed.Scheme, rawURL)
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()

	return c.domainAt(ctx, rawURL)
}

// fetchAt is the shared fetch-and-parse core behind Domain, IP, and ASN:
// one 429 retry honoring Retry-After, 404 mapped to ErrDomainNotFound with
// the Result still populated, rdapError title decoding for other 4xx/5xx,
// and MalformedResponseError for anything that isn't a JSON object of the
// expected objectClassName.
//
// A free function rather than a method on *Client because Go does not
// allow type parameters on methods.
func fetchAt[T rdapObject](
	c *Client,
	ctx context.Context,
	reqURL, wantClass string,
	assign func(*Result, *T),
) (*Result, error) {
	resp, err := c.do(ctx, reqURL)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		select {
		case <-time.After(retryAfter(resp.Header)):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		resp, err = c.do(ctx, reqURL)
		if err != nil {
			return nil, err
		}
	}

	contentType := resp.Header.Get("Content-Type")
	mediaType, _, _ := mime.ParseMediaType(contentType)
	conformant := mediaType == "application/rdap+json"

	result := &Result{
		Raw:                 resp.Body,
		StatusCode:          resp.StatusCode,
		ContentType:         contentType,
		MediaTypeConformant: conformant,
	}

	if resp.StatusCode == http.StatusNotFound {
		return result, ErrDomainNotFound
	}

	if resp.StatusCode >= 400 {
		var rerr rdapError
		if json.Unmarshal(bytes.TrimSpace(resp.Body), &rerr) == nil && rerr.Title != "" {
			return result, fmt.Errorf("rdap: %s returned %d: %s", reqURL, resp.StatusCode, rerr.Title)
		}
		return result, &MalformedResponseError{
			URL: reqURL, StatusCode: resp.StatusCode, ContentType: contentType,
			Snippet: snippet(resp.Body),
		}
	}

	trimmed := bytes.TrimSpace(resp.Body)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return result, &MalformedResponseError{
			URL: reqURL, StatusCode: resp.StatusCode, ContentType: contentType,
			Snippet: snippet(resp.Body),
		}
	}

	var obj T
	if err := json.Unmarshal(trimmed, &obj); err != nil {
		return result, &MalformedResponseError{
			URL: reqURL, StatusCode: resp.StatusCode, ContentType: contentType,
			Snippet: snippet(resp.Body), Err: err,
		}
	}

	if obj.objectClass() != wantClass {
		var rerr rdapError
		if json.Unmarshal(trimmed, &rerr) == nil && rerr.ErrorCode != 0 {
			return result, fmt.Errorf("rdap: %s returned errorCode %d: %s", reqURL, rerr.ErrorCode, rerr.Title)
		}
		return result, &MalformedResponseError{
			URL: reqURL, StatusCode: resp.StatusCode, ContentType: contentType,
			Snippet: snippet(resp.Body),
		}
	}

	assign(result, &obj)
	return result, nil
}

// domainAt fetches and decodes a domain object via fetchAt. Used by both
// Domain and DomainURL.
func (c *Client) domainAt(ctx context.Context, reqURL string) (*Result, error) {
	return fetchAt(c, ctx, reqURL, "domain",
		func(r *Result, d *DomainResponse) { r.Domain = d })
}

// IP queries baseURL for the given address's network object. baseURL is
// the RIR's RDAP service base, typically resolved via bootstrap's
// IPBaseURL.
func (c *Client) IP(ctx context.Context, baseURL string, addr netip.Addr) (*Result, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()

	reqURL := strings.TrimRight(baseURL, "/") + "/ip/" + url.PathEscape(addr.String())
	return c.ipAt(ctx, reqURL)
}

// ipAt fetches and decodes an IP network object via fetchAt.
func (c *Client) ipAt(ctx context.Context, reqURL string) (*Result, error) {
	return fetchAt(c, ctx, reqURL, "ip network",
		func(r *Result, n *IPNetworkResponse) { r.IPNetwork = n })
}

// ASN queries baseURL for the given autonomous system number's autnum
// object. baseURL is the RIR's RDAP service base, typically resolved via
// bootstrap's ASNBaseURL.
func (c *Client) ASN(ctx context.Context, baseURL string, asn uint32) (*Result, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()

	reqURL := strings.TrimRight(baseURL, "/") + "/autnum/" + strconv.FormatUint(uint64(asn), 10)
	return c.asnAt(ctx, reqURL)
}

// asnAt fetches and decodes an autnum object via fetchAt.
func (c *Client) asnAt(ctx context.Context, reqURL string) (*Result, error) {
	return fetchAt(c, ctx, reqURL, "autnum",
		func(r *Result, a *ASNResponse) { r.ASN = a })
}
