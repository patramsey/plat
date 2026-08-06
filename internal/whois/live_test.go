//go:build live

package whois

import (
	"context"
	"testing"
	"time"

	"github.com/patramsey/plat/internal/domain"
)

func TestLive_GoogleCom(t *testing.T) {
	q, err := domain.Normalize("google.com")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	c := &Client{Timeout: 10 * time.Second}
	result, err := c.Lookup(context.Background(), q.Name)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	deepest := result.Deepest()
	if deepest == nil {
		t.Fatal("no successful hop")
	}
	if deepest.Fields.Registrar == "" {
		t.Error("expected a registrar name from the deepest successful hop")
	}
	t.Logf("chain: %d hops, deepest server %s, registrar %q", len(result.Hops), deepest.Server, deepest.Fields.Registrar)
}
