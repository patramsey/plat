package domain

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"golang.org/x/net/idna"
)

// ErrSingleLabel is returned when the input has no dot at all (e.g.
// "localhost"), which can never be a registrable domain.
var ErrSingleLabel = errors.New("domain: single-label input is not a valid domain")

var reservedTLDs = map[string]bool{
	"local":    true,
	"internal": true,
	"test":     true,
	"example":  true,
	"invalid":  true,
}

// Name holds a normalized domain name in both its ASCII/LDH (punycode) and
// Unicode display forms, plus its top-level label.
type Name struct {
	Punycode string
	Unicode  string
	TLD      string
}

// Normalize lowercases, strips a trailing dot, reduces a pasted URL down to
// its bare host, converts IDN input to punycode, extracts the TLD, and
// rejects single-label or reserved/private TLD input with a friendly error.
func Normalize(input string) (Name, error) {
	s := strings.ToLower(strings.TrimSpace(input))
	s = stripURLParts(s)
	if s == "" {
		return Name{}, fmt.Errorf("domain: empty input")
	}

	// idna.Lookup (not the bare idna.ToASCII/Punycode profile) is
	// x/net/idna's own recommended profile for domain-name lookups: it
	// runs UTS46 mapping, which both applies NFC normalization (so
	// visually-identical NFC/NFD input punycodes identically) and treats
	// the CJK dot-equivalents (U+3002, U+FF0E, U+FF61) as label
	// separators alongside ASCII '.'. Because that mapping runs before
	// label splitting, any of those trailing dot forms survive as a
	// trailing ASCII '.' in the output — trimmed below the same way a
	// literal trailing '.' in the input already was.
	punycode, err := idna.Lookup.ToASCII(s)
	if err != nil {
		return Name{}, fmt.Errorf("domain: invalid domain name %q: %w", input, err)
	}
	punycode = strings.TrimSuffix(punycode, ".")

	labels := strings.Split(punycode, ".")
	if len(labels) < 2 {
		return Name{}, fmt.Errorf("%w: %q", ErrSingleLabel, input)
	}

	tld := labels[len(labels)-1]
	if reservedTLDs[tld] {
		return Name{}, fmt.Errorf("domain: %q is a reserved/private TLD and cannot be looked up", tld)
	}

	unicodeName, err := idna.ToUnicode(punycode)
	if err != nil {
		unicodeName = punycode
	}

	return Name{Punycode: punycode, Unicode: unicodeName, TLD: tld}, nil
}

// stripURLParts reduces a pasted URL down to its bare host, discarding any
// scheme, userinfo, port, path, query, and fragment — e.g.
// "https://example.com:8080/whois?x=1" becomes "example.com". This matters
// because domain lookups are frequently copy-pasted straight out of a
// browser's address bar rather than typed as a bare domain. url.Parse needs
// a scheme to recognize the rest as an authority component rather than an
// opaque path, so a bare host (no "://") is parsed as protocol-relative
// ("//host...") to get the same authority parsing without inventing a real
// scheme. Any input url.Parse can't make sense of passes through unchanged
// (Name normally never contains ':' or '/' anyway, and idna.ToASCII on the
// next line remains the source of truth for whether the result is a valid
// domain).
func stripURLParts(s string) string {
	target := s
	if !strings.Contains(s, "://") {
		target = "//" + s
	}
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return s
	}
	return u.Hostname()
}
