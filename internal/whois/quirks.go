package whois

import (
	"net"
	"strings"
)

// Quirk describes how to construct a WHOIS query for servers that don't
// accept a bare domain name — some registries require a prefix or suffix
// to avoid ambiguous matches or to request non-default output.
type Quirk struct {
	HostSuffix string
	Prefix     string
	Suffix     string
}

var quirks = []Quirk{
	{HostSuffix: "verisign-grs.com", Prefix: "domain "},
	{HostSuffix: "jprs.jp", Suffix: "/e"},
	{HostSuffix: "denic.de", Prefix: "-T dn,ace "},
}

// BuildQuery constructs the exact query line (without the trailing CRLF)
// to send to server for domain, applying any matching quirk. server may
// be a bare hostname or a host:port pair (quirk matching strips the port).
func BuildQuery(server, domain string) string {
	host := server
	if h, _, err := net.SplitHostPort(server); err == nil {
		host = h
	}
	host = strings.ToLower(host)
	for _, q := range quirks {
		// A label-boundary match, not a raw character-suffix match: a
		// host merely ending in the same characters as a known registry
		// host (e.g. "evildenic.de") isn't actually that registry's
		// server, only a genuine exact match or subdomain ("*.denic.de")
		// is.
		if host == q.HostSuffix || strings.HasSuffix(host, "."+q.HostSuffix) {
			return q.Prefix + domain + q.Suffix
		}
	}
	return domain
}

// registryFallback names a TLD's registry WHOIS server for when IANA's
// record lists none but the registry still runs one. It fills a gap in
// IANA's data and never overrides it: Lookup consults this only after the
// IANA hop answered without a server, so a registry that moves its server
// and updates IANA is followed there.
//
// .uk: IANA's record has carried an empty "whois:" line since
// 2026-08-04, while whois.nic.uk continues to answer. Without this entry
// a .uk lookup had RDAP as its only source, so one slow RDAP response
// failed the whole lookup.
var registryFallback = map[string]string{
	"uk": "whois.nic.uk",
}
