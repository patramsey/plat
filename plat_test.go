package plat

import (
	"context"
	"testing"

	"github.com/patramsey/plat/internal/whois"
)

func TestNew_DefaultsAreApplied(t *testing.T) {
	c, err := New(context.Background(), Options{
		DisableCache: true,
		Resolver:     NewResolver(map[string]string{}),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.opts.Timeout != defaultTimeout {
		t.Errorf("Timeout = %v, want %v", c.opts.Timeout, defaultTimeout)
	}
	if c.limiter == nil {
		t.Error("limiter is nil; bulk consumers would get no WHOIS pacing")
	}
	if c.ianaCache == nil {
		t.Error("ianaCache is nil")
	}
	if c.resolver == nil {
		t.Error("resolver is nil")
	}
}

func TestNew_WHOISIntervalDefaultsToPackageDefault(t *testing.T) {
	c, err := New(context.Background(), Options{
		DisableCache: true,
		Resolver:     NewResolver(map[string]string{}),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := c.interval; got != whois.DefaultWHOISInterval {
		t.Errorf("interval = %v, want %v", got, whois.DefaultWHOISInterval)
	}
}
