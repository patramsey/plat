package netguard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestAllowed(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{"192.0.32.59", true},         // whois.iana.org
		{"2001:500:88:200::59", true}, // whois.iana.org over IPv6
		{"8.8.8.8", true},
		{"127.0.0.1", false},
		{"::1", false},
		{"10.0.0.5", false},
		{"172.16.0.1", false},
		{"192.168.1.1", false},
		{"fd00:ec2::254", false}, // AWS's IPv6 metadata address
		{"169.254.169.254", false},
		{"fe80::1", false},
		{"0.0.0.0", false},
		{"::", false},
		{"0.1.2.3", false},
		{"100.100.100.200", false}, // shared address space
		{"192.0.0.192", false},
		{"198.18.0.1", false},
		{"240.0.0.1", false},
		{"224.0.0.1", false},
		{"ff02::1", false},
		{"::ffff:127.0.0.1", false}, // IPv4-mapped loopback
		{"::ffff:10.0.0.5", false},
		{"::ffff:8.8.8.8", true},
	}
	for _, tt := range tests {
		if got := Allowed(netip.MustParseAddr(tt.addr)); got != tt.want {
			t.Errorf("Allowed(%s) = %v, want %v", tt.addr, got, tt.want)
		}
	}
	if Allowed(netip.Addr{}) {
		t.Error("Allowed(zero Addr) = true, want false")
	}
}

func TestControl(t *testing.T) {
	if err := Control("tcp", "8.8.8.8:43", nil); err != nil {
		t.Errorf("public address: %v", err)
	}
	var refused *RefusedError
	if err := Control("tcp", "[::ffff:10.0.0.5]:6379", nil); !errors.As(err, &refused) || refused.Addr.String() != "10.0.0.5" {
		t.Errorf("mapped private address: err = %v, want RefusedError for 10.0.0.5", err)
	}
	if err := Control("tcp", "not-an-address", nil); err == nil || errors.As(err, &refused) {
		t.Errorf("malformed address: err = %v, want a non-refusal error", err)
	}
}

// TestDialer_RefusesLoopbackListener dials a real loopback listener: the
// connection must be refused before it is made, so the listener never
// sees it.
func TestDialer_RefusesLoopbackListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	accepted := make(chan struct{}, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			accepted <- struct{}{}
			_ = c.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := Dialer().DialContext(ctx, "tcp", ln.Addr().String())
	if err == nil {
		_ = conn.Close()
		t.Fatal("dial to a loopback listener succeeded, want refusal")
	}
	var refused *RefusedError
	if !errors.As(err, &refused) {
		t.Fatalf("err = %v, want a RefusedError", err)
	}
	select {
	case <-accepted:
		t.Fatal("listener accepted a connection that should have been refused")
	case <-time.After(100 * time.Millisecond):
	}
}
