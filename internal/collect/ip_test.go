package collect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/patramsey/plat/internal/model"
)

const arinIPBody = `{
  "objectClassName": "ip network",
  "handle": "NET-8-8-8-0-2",
  "startAddress": "8.8.8.0",
  "endAddress": "8.8.8.255",
  "ipVersion": "v4",
  "name": "GOGL",
  "type": "DIRECT ALLOCATION",
  "parentHandle": "NET-8-0-0-0-0",
  "status": ["active"],
  "cidr0_cidrs": [{"v4prefix": "8.8.8.0", "length": 24}],
  "events": [{"eventAction": "registration", "eventDate": "2023-12-28T17:24:33-05:00"}],
  "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Google LLC"]]]}]
}`

const arinIPWHOISText = "NetRange:       8.8.8.0 - 8.8.8.255\nCIDR:           8.8.8.0/24\nNetName:        GOGL\nNetHandle:      NET-8-8-8-0-2\nParent:         NET-8-0-0-0-0\nNetType:        Direct Allocation\nOrgName:        Google LLC\nOrgId:          GOGL\nCountry:        US\nRegDate:        2023-12-28\nUpdated:        2023-12-29\n"

func TestCollectIP_RegistryRDAPPlusWHOIS(t *testing.T) {
	rdapSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(arinIPBody))
	}))
	defer rdapSrv.Close()

	rirWHOISAddr := startWHOISListener(t, func(query string) string {
		return arinIPWHOISText
	})
	ianaWHOISAddr := startWHOISListener(t, func(query string) string {
		return "refer:        " + rirWHOISAddr + "\n"
	})

	addr := netip.MustParseAddr("8.8.8.8")

	records := CollectIP(context.Background(), addr, rdapSrv.URL, ianaWHOISAddr, Options{Timeout: 2 * time.Second})

	if len(records) != 2 {
		t.Fatalf("len(records) = %d, want 2, got: %+v", len(records), records)
	}
	if records[0].Meta.Source != model.SourceRegistryRDAP {
		t.Errorf("records[0].Meta.Source = %q, want %q (fixed order)", records[0].Meta.Source, model.SourceRegistryRDAP)
	}
	if !records[0].Present {
		t.Errorf("records[0].Present = false, want true: %+v", records[0])
	}
	if records[1].Meta.Source != model.SourceRegistryWHOIS {
		t.Errorf("records[1].Meta.Source = %q, want %q (fixed order)", records[1].Meta.Source, model.SourceRegistryWHOIS)
	}
	if !records[1].Present {
		t.Errorf("records[1].Present = false, want true: %+v", records[1])
	}
	if records[0].OrgName != "Google LLC" {
		t.Errorf("records[0].OrgName = %q, want Google LLC", records[0].OrgName)
	}
	if records[1].OrgName != "Google LLC" {
		t.Errorf("records[1].OrgName = %q, want Google LLC", records[1].OrgName)
	}
}

func TestCollectIP_EmptyBaseURLDegradesToWHOISOnly(t *testing.T) {
	rirWHOISAddr := startWHOISListener(t, func(query string) string {
		return arinIPWHOISText
	})
	ianaWHOISAddr := startWHOISListener(t, func(query string) string {
		return "refer:        " + rirWHOISAddr + "\n"
	})

	addr := netip.MustParseAddr("8.8.8.8")

	records := CollectIP(context.Background(), addr, "", ianaWHOISAddr, Options{Timeout: 2 * time.Second})

	if len(records) != 1 {
		t.Fatalf("len(records) = %d, want 1 (WHOIS-only), got: %+v", len(records), records)
	}
	if records[0].Meta.Source != model.SourceRegistryWHOIS {
		t.Errorf("records[0].Meta.Source = %q, want %q", records[0].Meta.Source, model.SourceRegistryWHOIS)
	}
	if !records[0].Present {
		t.Errorf("records[0].Present = false, want true: %+v", records[0])
	}
}

func TestCollectIP_NotFoundBothSources(t *testing.T) {
	rdapSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer rdapSrv.Close()

	rirWHOISAddr := startWHOISListener(t, func(query string) string {
		return "No match found for 8.8.8.8.\n"
	})
	ianaWHOISAddr := startWHOISListener(t, func(query string) string {
		return "refer:        " + rirWHOISAddr + "\n"
	})

	addr := netip.MustParseAddr("8.8.8.8")

	records := CollectIP(context.Background(), addr, rdapSrv.URL, ianaWHOISAddr, Options{Timeout: 2 * time.Second})

	if len(records) != 2 {
		t.Fatalf("len(records) = %d, want 2, got: %+v", len(records), records)
	}
	for _, r := range records {
		if r.Meta.OK {
			t.Errorf("source %s: Meta.OK = true, want false for a not-found response", r.Meta.Source)
		}
		if !r.Meta.NotFound {
			t.Errorf("source %s: Meta.NotFound = false, want true", r.Meta.Source)
		}
		if r.Present {
			t.Errorf("source %s: Present = true, want false for a not-found response", r.Meta.Source)
		}
	}
}

func TestCollectIP_SourceFilter(t *testing.T) {
	rdapSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("RDAP server should never be contacted when --source whois is set")
	}))
	defer rdapSrv.Close()

	rirWHOISAddr := startWHOISListener(t, func(query string) string {
		return arinIPWHOISText
	})
	ianaWHOISAddr := startWHOISListener(t, func(query string) string {
		return "refer:        " + rirWHOISAddr + "\n"
	})

	addr := netip.MustParseAddr("8.8.8.8")

	records := CollectIP(context.Background(), addr, rdapSrv.URL, ianaWHOISAddr, Options{
		Timeout: 2 * time.Second,
		Sources: []model.SourceID{model.SourceRegistryWHOIS},
	})

	if len(records) != 1 {
		t.Fatalf("len(records) = %d, want 1, got: %+v", len(records), records)
	}
	if records[0].Meta.Source != model.SourceRegistryWHOIS {
		t.Errorf("records[0].Meta.Source = %q, want %q", records[0].Meta.Source, model.SourceRegistryWHOIS)
	}
}
