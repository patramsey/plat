package plat_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/patramsey/plat"
)

// ExampleClient_Lookup shows the New/Lookup shape. It performs real
// network I/O, so it has no "// Output:" comment: godoc renders it, but
// go test does not execute it.
func ExampleClient_Lookup() {
	c, err := plat.New(context.Background(), plat.Options{})
	if err != nil {
		panic(err)
	}

	res, err := c.Lookup(context.Background(), "example.com")
	switch {
	case errors.Is(err, plat.ErrNotFound):
		fmt.Println("no such object")
		return
	case err != nil:
		panic(err)
	}

	switch res.Kind {
	case plat.KindDomain:
		fmt.Println(res.Domain.Expires.Value.Time, res.Domain.Expires.Sources)
	case plat.KindIP:
		fmt.Println(res.IP.CIDR.Value)
	case plat.KindASN:
		fmt.Println(res.ASN.Name.Value)
	}
}

// ExampleOptions shows how a program doing many lookups would tune a
// Client: no disk cache, a longer per-lookup budget, and only the two
// RDAP sources consulted. It builds no Client and performs no I/O, so it
// is safe to run as part of the test suite.
func ExampleOptions() {
	_ = plat.Options{
		Timeout:      30 * time.Second,
		DisableCache: true,
		Sources: []plat.SourceID{
			plat.SourceRegistryRDAP,
			plat.SourceRegistrarRDAP,
		},
	}
	fmt.Println("configured")
	// Output: configured
}

// ExampleEncodeJSON builds a Record by hand -- no lookup, no network -- and
// encodes it the same way the CLI's -o json would. Its output is
// deterministic, so it runs as part of the test suite.
func ExampleEncodeJSON() {
	rec := plat.Record{
		Domain: plat.Field[string]{
			Value:   "example.com",
			Sources: []plat.SourceID{plat.SourceRegistryRDAP},
		},
	}
	res := plat.Result{Kind: plat.KindDomain, Input: "example.com", Domain: &rec}

	var buf bytes.Buffer
	if err := plat.EncodeJSON(&buf, res, plat.EncodeOptions{}); err != nil {
		panic(err)
	}
	fmt.Println(buf.String())
	// Output: {"schemaVersion":1,"objectType":"domain","domain":{"value":"example.com","sources":["registry-rdap"]},"conflicts":[],"redacted":[],"sources":[]}
}
