// Package netguard decides which addresses a referral may connect to.
//
// WHOIS and RDAP answers name the next server to query: IANA's refer:
// line, a registry's Registrar WHOIS Server: line, RDAP's port43 field and
// its registrar link. Whoever writes those answers -- a registry, a
// registrar, or anyone on the path of plaintext WHOIS -- would otherwise
// choose where plat connects, including services on the caller's own
// network (GHSA-8q76-8r67-p8g8). No real referral names a loopback,
// private or link-local address, so a referral connection to one is
// refused. Servers the caller configures are never checked.
package netguard

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"
)

// RefusedError is returned when a referral connection would reach an
// address that is not publicly routable.
type RefusedError struct {
	Addr netip.Addr
}

func (e *RefusedError) Error() string {
	return fmt.Sprintf("refusing to connect to %s: a referral may not name a non-public address", e.Addr)
}

// blocked are ranges net/netip has no predicate for but that never host a
// public WHOIS or RDAP server: "this network", shared address space
// (carrier-grade NAT, and some clouds' metadata service), the IETF
// protocol-assignment block, benchmarking, and the reserved class E.
var blocked = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

// Allowed reports whether a referral may connect to addr. IPv4-mapped
// IPv6 addresses are judged as the IPv4 address they carry.
func Allowed(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() || addr.IsUnspecified() || addr.IsLoopback() || addr.IsPrivate() ||
		addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() ||
		addr.IsInterfaceLocalMulticast() || addr.IsMulticast() {
		return false
	}
	for _, p := range blocked {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}

// Control is a net.Dialer Control function that refuses a connection to
// an address Allowed rejects. It runs after name resolution, once per
// address the dialer tries, so a hostname that resolves to a private
// address is refused as surely as an IP literal.
func Control(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("netguard: unexpected dial address %q: %w", address, err)
	}
	if !Allowed(ap.Addr()) {
		return &RefusedError{Addr: ap.Addr().Unmap()}
	}
	return nil
}

// Dialer returns a net.Dialer that refuses non-public addresses.
func Dialer() *net.Dialer {
	return &net.Dialer{Control: Control}
}
