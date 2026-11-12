// Package testnet lets tests chase WHOIS referrals to local listeners.
//
// plat follows a referral only on port 43, and its own dialer refuses a
// referral that resolves to a loopback address, so a test's answer
// cannot refer to a listener at 127.0.0.1:NNNN. It refers to a name such
// as "registry.test" instead, and the test passes Net.Dial as the WHOIS
// dialer, which maps that name onto the listener the way DNS maps a real
// referral's name onto a server.
package testnet

import (
	"context"
	"fmt"
	"net"
	"sync"
)

// Net maps host names to listener addresses ("127.0.0.1:NNNN").
type Net map[string]string

// Dial connects to the listener mapped to addr's host when addr is on
// port 43, and to addr as given otherwise -- a configured IANA server
// such as 127.0.0.1:NNNN, or a host the test left unmapped.
func (n Net) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if host, port, err := net.SplitHostPort(addr); err == nil && port == "43" {
		if target, ok := n[host]; ok {
			addr = target
		}
	}
	return (&net.Dialer{}).DialContext(ctx, network, addr)
}

// Registry hands out a unique name for each listener a test starts, so a
// test helper can return the name in place of the address and every
// answer, configured server and assertion in the test uses names. Safe
// for concurrent use.
type Registry struct {
	mu sync.Mutex
	n  int
	m  Net
}

// Add registers addr and returns its name, of the form "whois-N.test".
func (r *Registry) Add(addr string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.m == nil {
		r.m = Net{}
	}
	r.n++
	name := fmt.Sprintf("whois-%d.test", r.n)
	r.m[name] = addr
	return name
}

// Dial is Net.Dial over every name Add has handed out.
func (r *Registry) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err == nil && port == "43" {
		r.mu.Lock()
		target, ok := r.m[host]
		r.mu.Unlock()
		if ok {
			addr = target
		}
	}
	return (&net.Dialer{}).DialContext(ctx, network, addr)
}
