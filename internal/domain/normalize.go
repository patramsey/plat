package domain

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// ErrSingleLabel is returned when the input has no dot at all (e.g.
// "localhost"), which can never be a registrable domain.
var ErrSingleLabel = errors.New("single-label input is not a valid domain")

// ErrEmptyLabel is returned when a name contains a zero-length label
// ("a..com", ".com"). idna.Lookup.ToASCII accepts these without error --
// and rewrites "xn--.com" to ".com", which the len(labels) < 2 guard then
// waves through as a two-label name, so plat would look up .com instead of
// the name it was given. The check therefore has to happen here, after the
// split, rather than being left to idna.
var ErrEmptyLabel = errors.New("domain name contains an empty label")

// ErrReservedIP is returned when input names a reserved, private, or
// otherwise special-purpose IP address (RFC 1918/4193 private space,
// loopback, link-local, multicast, unspecified, or the IPv4 limited
// broadcast address). None of these can have registry/registrar
// ownership data -- no RIR allocates them to an organization -- so
// there is nothing for RDAP/WHOIS to return. This is the IP counterpart
// of reservedTLDs' rejection of .local/.internal/etc for domains.
var ErrReservedIP = errors.New("reserved IP address")

// ErrReservedASN is returned for an IANA special-purpose autonomous
// system number -- reserved, AS_TRANS, documentation, or private use. No
// RIR allocates these to an organization, so, like a reserved IP, there
// is no registration data to look up. It is the ASN counterpart of
// ErrReservedIP.
var ErrReservedASN = errors.New("reserved ASN")

// ErrASNOutOfRange is returned for "AS" followed by a number too large
// for the 32-bit ASN space. The input is unmistakably an ASN attempt, so
// it must not fall through to the domain path and be reported as a
// single-label domain.
var ErrASNOutOfRange = errors.New("ASN out of range")

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
	// Host is the full hostname given when Name is its registered domain
	// instead ("www.google.com" for google.com), and "" when nothing was
	// dropped. KindDomain only.
	Host string
}

// Normalize lowercases, strips a trailing dot, reduces a pasted URL down to
// its bare host, and classifies the input as either an IP address or a
// domain name. Domain input is further converted from IDN to punycode,
// reduced to its registered domain (see registeredDomain), its TLD
// extracted, and single-label or reserved/private TLD input rejected with
// a friendly error.
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
		return Query{}, errors.New("empty input")
	}
	// Catches the forms only stripURLParts can surface: a pasted URL
	// ("https://8.8.8.8/x") and the bracketed IPv6 host form.
	if addr, ok := parseIPInput(s); ok {
		return ipQuery(addr, input)
	}
	if asn, ok := parseASNInput(s); ok {
		if cat := reservedASNCategory(asn); cat != "" {
			return Query{}, fmt.Errorf("%w: %q is %s and has no registration data to look up", ErrReservedASN, input, cat)
		}
		return Query{Kind: KindASN, ASN: asn, Input: input}, nil
	}
	if isASNForm(s) {
		return Query{}, fmt.Errorf("%w: %q exceeds AS4294967295, the largest 32-bit ASN", ErrASNOutOfRange, input)
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
		return Query{}, fmt.Errorf("invalid domain name %q: %w", input, err)
	}
	punycode = strings.TrimSuffix(punycode, ".")

	labels := strings.Split(punycode, ".")
	if len(labels) < 2 {
		return Query{}, fmt.Errorf("%w: %q", ErrSingleLabel, input)
	}
	if slices.Contains(labels, "") {
		return Query{}, fmt.Errorf("%w: %q", ErrEmptyLabel, input)
	}

	tld := labels[len(labels)-1]
	if reservedTLDs[tld] {
		return Query{}, fmt.Errorf("%q is a reserved/private TLD and cannot be looked up", tld)
	}

	var host string
	if reg := registeredDomain(punycode); reg != punycode {
		host, punycode = punycode, reg
	}

	unicodeName, err := idna.ToUnicode(punycode)
	if err != nil {
		unicodeName = punycode
	}

	return Query{Kind: KindDomain, Name: Name{Punycode: punycode, Unicode: unicodeName, TLD: tld}, Input: input, Host: host}, nil
}

// registeredDomain reduces a hostname to the domain a registry actually
// registered: www.google.com to google.com, mail.google.co.uk to
// google.co.uk. Neither RDAP nor WHOIS holds a record for a subdomain, so
// looking one up as given answered "not registered" for a name pasted
// straight out of a browser -- confidently, and wrongly.
//
// The Public Suffix List says where registrations happen. Only its ICANN
// section counts: a private-section rule (github.io, blogspot.com) marks
// where a hosting provider hands out subdomains, and foo.github.io is
// registered by nobody but GitHub, as github.io. A TLD missing from the
// list falls to the default "*" rule, which also reports a private,
// single-label suffix -- the TLD itself -- so the walk stops there.
//
// A name that is itself a public suffix (co.uk) is returned unchanged.
func registeredDomain(name string) string {
	suffix, icann := publicsuffix.PublicSuffix(name)
	for !icann && strings.Contains(suffix, ".") {
		_, rest, _ := strings.Cut(suffix, ".")
		suffix, icann = publicsuffix.PublicSuffix(rest)
	}
	prefix, ok := strings.CutSuffix(name, "."+suffix)
	if !ok {
		return name
	}
	return prefix[strings.LastIndex(prefix, ".")+1:] + "." + suffix
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

// isASNForm reports whether s is "AS" followed only by digits -- the
// shape of an ASN whatever its value, so parseASNInput rejecting it can
// only mean the number is out of range.
func isASNForm(s string) bool {
	if len(s) < 3 || !strings.EqualFold(s[:2], "as") {
		return false
	}
	for _, r := range s[2:] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// reservedASNCategory reports why asn is an IANA special-purpose
// autonomous system number with no registration data to look up, or ""
// if it is an ordinary, potentially-allocated one. The ranges follow
// IANA's "Special-Purpose AS Numbers" registry.
func reservedASNCategory(asn uint32) string {
	switch {
	case asn == 0:
		return "reserved (RFC 7607)"
	case asn == 23456:
		return "AS_TRANS, the placeholder for a 4-byte ASN (RFC 6793)"
	case asn >= 64496 && asn <= 64511, asn >= 65536 && asn <= 65551:
		return "reserved for documentation (RFC 5398)"
	case asn >= 64512 && asn <= 65534, asn >= 4200000000 && asn <= 4294967294:
		return "reserved for private-use networks (RFC 6996)"
	case asn == 65535, asn == 4294967295:
		return "reserved (RFC 7300)"
	case asn >= 65552 && asn <= 131071:
		return "reserved by IANA"
	default:
		return ""
	}
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
	}
	for _, r := range reservedPrefixes {
		if r.prefix.Contains(addr) {
			return r.category
		}
	}
	return ""
}

// reservedPrefixes are special-purpose ranges net/netip has no predicate
// for. Without them the documentation ranges were answered three ways --
// "not registered" (2001:db8::/32, 203.0.113.0/24), "no server listed"
// (3fff::/20, 240.0.0.0/4), or IANA's TEST-NET record from ARIN
// (192.0.2.0/24, 198.51.100.0/24) -- none of which says the range can
// never be allocated (#125). 100.64.0.0/10 and 198.18.0.0/15 are left
// out on purpose: ARIN answers them with IANA's informative record.
var reservedPrefixes = []struct {
	prefix   netip.Prefix
	category string
}{
	{netip.MustParsePrefix("0.0.0.0/8"), `"this network" (RFC 791)`},
	{netip.MustParsePrefix("192.0.2.0/24"), "a documentation address (RFC 5737)"},
	{netip.MustParsePrefix("198.51.100.0/24"), "a documentation address (RFC 5737)"},
	{netip.MustParsePrefix("203.0.113.0/24"), "a documentation address (RFC 5737)"},
	{netip.MustParsePrefix("240.0.0.0/4"), "reserved for future use (RFC 1112)"},
	{netip.MustParsePrefix("2001:db8::/32"), "a documentation address (RFC 3849)"},
	{netip.MustParsePrefix("3fff::/20"), "a documentation address (RFC 9637)"},
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
