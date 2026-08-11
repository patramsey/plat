package domain

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

// ErrSingleLabel is returned when the input has no dot at all (e.g.
// "localhost"), which can never be a registrable domain.
var ErrSingleLabel = errors.New("domain: single-label input is not a valid domain")

// ErrReservedIP is returned when input names a reserved, private, or
// otherwise special-purpose IP address (RFC 1918/4193 private space,
// loopback, link-local, multicast, unspecified, or the IPv4 limited
// broadcast address). None of these can have registry/registrar
// ownership data -- no RIR allocates them to an organization -- so
// there is nothing for RDAP/WHOIS to return. This is the IP counterpart
// of reservedTLDs' rejection of .local/.internal/etc for domains.
var ErrReservedIP = errors.New("domain: reserved/private IP address cannot be looked up")

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
	KindASN
)

// Query is Normalize's result: a kind plus exactly one populated payload.
// Callers switch on Kind and read only the matching field.
type Query struct {
	Kind  Kind
	Name  Name       // KindDomain
	IP    netip.Addr // KindIPv4 / KindIPv6
	ASN   uint32     // KindASN
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
		return ipQuery(addr, input)
	}
	s = stripURLParts(s)
	if s == "" {
		return Query{}, fmt.Errorf("domain: empty input")
	}
	// Catches the forms only stripURLParts can surface: a pasted URL
	// ("https://8.8.8.8/x") and the bracketed IPv6 host form.
	if addr, ok := parseIPInput(s); ok {
		return ipQuery(addr, input)
	}
	if asn, ok := parseASNInput(s); ok {
		return Query{Kind: KindASN, ASN: asn, Input: input}, nil
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

// parseASNInput reports whether s names an autonomous system number in
// the "AS15169" form and returns it. A bare number is deliberately NOT
// accepted: it is likelier a typo'd domain than an intentional ASN, and
// silently treating it as one would turn a typo into a successful lookup
// of the wrong object.
func parseASNInput(s string) (uint32, bool) {
	if len(s) < 3 {
		return 0, false
	}
	if !strings.EqualFold(s[:2], "as") {
		return 0, false
	}
	n, err := strconv.ParseUint(s[2:], 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(n), true
}

// v4Broadcast is the IPv4 limited broadcast address, 255.255.255.255 --
// the one reserved-address case net/netip's Addr has no Is* predicate
// for (it isn't private, loopback, link-local, or multicast).
var v4Broadcast = netip.AddrFrom4([4]byte{255, 255, 255, 255})

// reservedIPCategory reports why addr is a reserved/special-purpose
// address with no registration data to look up, or "" if it's an
// ordinary, potentially-allocated address. Checked in a fixed order so
// an address matching more than one predicate (e.g. loopback addresses
// are also, incidentally, unspecified-adjacent) gets one clear reason
// rather than an arbitrary one -- though in practice net/netip's
// predicates are already mutually exclusive for every input this
// matters for.
func reservedIPCategory(addr netip.Addr) string {
	switch {
	case addr.IsUnspecified():
		return "the unspecified address"
	case addr.IsLoopback():
		return "a loopback address"
	case addr.Is4() && addr == v4Broadcast:
		return "the IPv4 limited broadcast address"
	case addr.IsPrivate():
		return "a private-use address"
	case addr.IsLinkLocalUnicast():
		return "a link-local address"
	case addr.IsLinkLocalMulticast(), addr.IsMulticast():
		return "a multicast address"
	default:
		return ""
	}
}

// ipQuery classifies addr into a Query, rejecting it up front with
// ErrReservedIP if it's reserved/private/special-purpose -- see
// reservedIPCategory. input is the original, pre-normalization string,
// preserved in both the error and a successful Query for user-facing
// messages.
func ipQuery(addr netip.Addr, input string) (Query, error) {
	if cat := reservedIPCategory(addr); cat != "" {
		return Query{}, fmt.Errorf("%w: %q is %s and has no registration data to look up", ErrReservedIP, input, cat)
	}
	kind := KindIPv6
	if addr.Is4() {
		kind = KindIPv4
	}
	return Query{Kind: kind, IP: addr, Input: input}, nil
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
