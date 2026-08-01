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
