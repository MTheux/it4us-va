package server

import (
	"encoding/json"
	"testing"

	"github.com/MTheux/it4us-va/vacheck"
)

func TestCVEApplicabilityIsConservative(t *testing.T) {
	rule := nvdMatch{Vulnerable: true, Criteria: "cpe:2.3:a:example:service:*:*:*:*:*:*:*:*", StartIncluding: "2.0", EndExcluding: "3.0"}
	for _, tc := range []struct {
		cpe, want string
		match     bool
	}{
		{"cpe:/a:example:service:2.4", "possible", true},
		{"cpe:/a:example:service:3.0", "", false},
		{"cpe:/a:example:service:2.4p1", "inconclusive", true},
		{"cpe:/a:other:service:2.4", "", false},
	} {
		got, matched := cpeApplies(tc.cpe, rule)
		if got != tc.want || matched != tc.match {
			t.Errorf("%q => %q %v, want %q %v", tc.cpe, got, matched, tc.want, tc.match)
		}
	}
	var feed nvdResponse
	if err := json.Unmarshal([]byte(`{"vulnerabilities":[{"cve":{"id":"CVE-2026-12345","descriptions":[{"lang":"en","value":"fixture"}],"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:example:service:*:*:*:*:*:*:*:*","versionStartIncluding":"2.0","versionEndExcluding":"3.0"}]}]}]}}]}`), &feed); err != nil {
		t.Fatal(err)
	}
	result := assessCVE("CVE-2026-12345", feed, []vacheck.Asset{{IP: "192.0.2.10", Port: 443, Service: "https", Version: "2.4", CPE: []string{"cpe:/a:example:service:2.4"}}})
	if result.Status != "possible" || len(result.Matches) != 1 || result.Matches[0].Status != "possible" {
		t.Fatalf("result=%+v", result)
	}
}
