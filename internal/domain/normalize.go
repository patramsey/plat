package domain

import (
	"errors"
	"fmt"
	"net/netip"
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

// Kind distinguishes what sort of object an input names. It is
// deliberately open to extension -- ASN support appends KindASN.
type Kind int

const (
	KindDomain Kind = iota
	KindIPv4
	KindIPv6
)

// Query is Normalize's result: a kind plus exactly one populated payload.
// Callers switch on Kind and read only the matching field.
type Query struct {
	Kind  Kind
	Name  Name       // KindDomain
	IP    netip.Addr // KindIPv4 / KindIPv6
	Input string     // the original input, for error messages
}

// Normalize lowercases, strips a trailing dot, reduces a pasted URL down to
// its bare host, and classifies the input as either an IP address or a
// domain name. Domain input is further converted from IDN to punycode, its
// TLD extracted, and single-label or reserved/private TLD input rejected
// with a friendly error.
func Normalize(input string) (Query, error) {
	s := strings.ToLower(strings.TrimSpace(input))
	// Classified before stripURLParts as well as after: that helper reads
	// a bare IPv6 address's trailing group as a port ("2001:db8::1"
	// becomes "2001:db8:"), so by the time it returns there's nothing
	// left that still parses as an IP.
	if addr, ok := parseIPInput(s); ok {
		return ipQuery(addr, input), nil
	}
	s = stripURLParts(s)
	if s == "" {
		return Query{}, fmt.Errorf("domain: empty input")
	}
	// Catches the forms only stripURLParts can surface: a pasted URL
	// ("https://8.8.8.8/x") and the bracketed IPv6 host form.
	if addr, ok := parseIPInput(s); ok {
		return ipQuery(addr, input), nil
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
		return Query{}, fmt.Errorf("domain: invalid domain name %q: %w", input, err)
	}
	punycode = strings.TrimSuffix(punycode, ".")

	labels := strings.Split(punycode, ".")
	if len(labels) < 2 {
		return Query{}, fmt.Errorf("%w: %q", ErrSingleLabel, input)
	}

	tld := labels[len(labels)-1]
	if reservedTLDs[tld] {
		return Query{}, fmt.Errorf("domain: %q is a reserved/private TLD and cannot be looked up", tld)
	}

	unicodeName, err := idna.ToUnicode(punycode)
	if err != nil {
		unicodeName = punycode
	}

	return Query{Kind: KindDomain, Name: Name{Punycode: punycode, Unicode: unicodeName, TLD: tld}, Input: input}, nil
}

// parseIPInput reports whether s names an IP address -- bare, in the
// bracketed form URLs use ("[2001:db8::1]"), or as a CIDR prefix
// ("8.8.8.0/24") -- and returns it. A CIDR resolves to its network
// address, since that is the block the registries are keyed on.
func parseIPInput(s string) (netip.Addr, bool) {
	trimmed := strings.Trim(s, "[]")
	if addr, err := netip.ParseAddr(trimmed); err == nil {
		return addr.Unmap(), true
	}
	if prefix, err := netip.ParsePrefix(trimmed); err == nil {
		return prefix.Masked().Addr().Unmap(), true
	}
	return netip.Addr{}, false
}

func ipQuery(addr netip.Addr, input string) Query {
	kind := KindIPv6
	if addr.Is4() {
		kind = KindIPv4
	}
	return Query{Kind: kind, IP: addr, Input: input}
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
