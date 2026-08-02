package main

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/patramsey/plat/internal/bootstrap"
	"github.com/patramsey/plat/internal/render"
)

func startFakeWHOISListener(t *testing.T, respond func(query string) string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				buf := make([]byte, 4096)
				n, _ := conn.Read(buf)
				query := strings.TrimRight(string(buf[:n]), "\r\n")
				_, _ = conn.Write([]byte(respond(query)))
			}()
		}
	}()
	return ln.Addr().String()
}

func TestLookupOne_HappyPath_RDAPAndWHOIS(t *testing.T) {
	fixture, err := os.ReadFile("../../testdata/rdap/com-example.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	rdapSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(fixture)
	}))
	defer rdapSrv.Close()

	registryWHOISAddr := startFakeWHOISListener(t, func(query string) string {
		return "Domain Name: EXAMPLE.COM\nRegistrar: Example Registrar, Inc.\n"
	})
	ianaAddr := startFakeWHOISListener(t, func(query string) string {
		return "refer: " + registryWHOISAddr + "\n"
	})

	resolver := bootstrap.NewResolver(map[string]string{"com": rdapSrv.URL})

	var stdout, stderr bytes.Buffer
	code := lookupOne(
		context.Background(), &stdout, &stderr, resolver, "example.com",
		lookupOptions{whoisIANAServer: ianaAddr, NoFollow: true},
		nil, render.FormatJSON, uiConfig{},
	)

	if code != 0 {
		t.Errorf("exit code = %d, want 0\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "example.com") {
		t.Errorf("stdout missing domain, got:\n%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Example Registrar") {
		t.Errorf("stdout missing WHOIS-sourced registrar name, got:\n%s", stdout.String())
	}
}
