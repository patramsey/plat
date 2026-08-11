package collect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/patramsey/plat/internal/model"
)

const arinASNBody = `{
  "objectClassName": "autnum",
  "handle": "AS15169",
  "startAutnum": 15169,
  "endAutnum": 15169,
  "name": "GOOGLE",
  "type": "DIRECT ALLOCATION",
  "status": ["active"],
  "events": [{"eventAction": "registration", "eventDate": "2000-03-30T00:00:00Z"}],
  "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Google LLC"]]]}]
}`

const arinASNWHOISText = "ASNumber:       15169\nASName:         GOOGLE\nASHandle:       AS15169\nOrgName:        Google LLC\nOrgId:          GOGL\nRegDate:        2000-03-30\nUpdated:        2012-02-24\n"

func TestCollectASN_RegistryRDAPPlusWHOIS(t *testing.T) {
	rdapSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(arinASNBody))
	}))
	defer rdapSrv.Close()

	rirWHOISAddr := startWHOISListener(t, func(query string) string {
		return arinASNWHOISText
	})
	ianaWHOISAddr := startWHOISListener(t, func(query string) string {
		return "refer:        " + rirWHOISAddr + "\n"
	})

	records := CollectASN(context.Background(), 15169, rdapSrv.URL, ianaWHOISAddr, Options{Timeout: 2 * time.Second})

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

func TestCollectASN_EmptyBaseURLDegradesToWHOISOnly(t *testing.T) {
	rirWHOISAddr := startWHOISListener(t, func(query string) string {
		return arinASNWHOISText
	})
	ianaWHOISAddr := startWHOISListener(t, func(query string) string {
		return "refer:        " + rirWHOISAddr + "\n"
	})

	records := CollectASN(context.Background(), 15169, "", ianaWHOISAddr, Options{Timeout: 2 * time.Second})

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
