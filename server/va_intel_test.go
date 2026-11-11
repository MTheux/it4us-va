package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNVDIntelSeparatesExploitReferencesAndRejectsUnsafeLinks(t *testing.T) {
	var payload nvdResponse
	data := `{"vulnerabilities":[{"cve":{"id":"CVE-2024-6387","published":"2024-07-01T00:00:00.000","descriptions":[{"lang":"en","value":"Example"}],"references":[{"url":"https://vendor.example/advisory","source":"Vendor","tags":["Vendor Advisory"]},{"url":"https://research.example/poc","source":"Research","tags":["Exploit"]},{"url":"javascript:alert(1)","tags":["Exploit"]}]}}]}`
	if err := json.Unmarshal([]byte(data), &payload); err != nil {
		t.Fatal(err)
	}
	got := nvdIntel(payload.Vulnerabilities[0].CVE)
	if got.Description != "Example" || len(got.ExploitReferences) != 1 || len(got.References) != 1 {
		t.Fatalf("unexpected intel result: %+v", got)
	}
}

func TestLookupEPSSBoundsAndParsesScore(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("cve") != "CVE-2024-6387" {
			t.Errorf("unexpected query %q", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`{"data":[{"cve":"CVE-2024-6387","epss":"0.25","percentile":"0.91"}]}`))
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	score, percentile, err := lookupEPSSFrom(ctx, srv.Client(), srv.URL, "CVE-2024-6387")
	if err != nil {
		t.Fatal(err)
	}
	if score == nil || percentile == nil || *score != 0.25 || *percentile != 0.91 {
		t.Fatalf("unexpected scores: %v %v", score, percentile)
	}
}

func TestLookupGHSAAcceptsOnlyMatchingCVEAndSafeURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("cve_id") != "CVE-2024-12345" {
			t.Errorf("unexpected query %q", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`[{"cve_id":"CVE-2024-12345","ghsa_id":"GHSA-aaaa-bbbb-cccc","html_url":"https://github.com/advisories/GHSA-aaaa-bbbb-cccc"},{"cve_id":"CVE-2024-99999","html_url":"https://github.com/advisories/other"},{"cve_id":"CVE-2024-12345","html_url":"javascript:alert(1)"}]`))
	}))
	defer srv.Close()
	items, err := lookupGHSAFrom(context.Background(), srv.Client(), srv.URL, "CVE-2024-12345")
	if err != nil || len(items) != 1 || items[0].Source != "GHSA-aaaa-bbbb-cccc" {
		t.Fatalf("unexpected advisories: %+v err=%v", items, err)
	}
}
