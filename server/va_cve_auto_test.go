package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/MTheux/it4us-va/vacheck"
	"github.com/MTheux/it4us-va/vascan"
)

func TestNVDCPENeedsConcreteVersion(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{"cpe:/a:example:service:2.4", "cpe:2.3:a:example:service:2.4:*:*:*:*:*:*:*"},
		{"cpe:2.3:a:example:service:2.4:*:*:*:*:*:*:*", "cpe:2.3:a:example:service:2.4:*:*:*:*:*:*:*"},
		{"cpe:/a:example:service:*", ""},
		{"cpe:/a:example:service", ""},
		{"example service 2.4", ""},
	} {
		got, ok := nvdCPEName(tc.raw)
		if got != tc.want || ok != (tc.want != "") {
			t.Errorf("%q => %q %v, want %q", tc.raw, got, ok, tc.want)
		}
	}
}

func TestAutoCVEFromObservedCPEKeepsFindingPending(t *testing.T) {
	s, fixture, _ := trafficEvidenceServer(t)
	var taskID int64
	if err := s.m.pg.QueryRow(`SELECT task_id FROM findings WHERE id=$1`, fixture.FindingID).Scan(&taskID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.m.pg.DeleteFindingsByTask(taskID) })
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Query().Get("cpeName"), "example:service:2.4") || r.URL.Query().Get("resultsPerPage") != "200" {
			t.Errorf("unexpected NVD query: %s", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2026-12345","descriptions":[{"lang":"en","value":"fixture"}],"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:example:service:*:*:*:*:*:*:*:*","versionStartIncluding":"2.0","versionEndExcluding":"3.0"}]}]}]}}]}`))
	}))
	defer remote.Close()
	makeRecord := func() vaRunRecord {
		return vaRunRecord{Campaign: vascan.Campaign{TaskID: taskID}, Result: &vascan.Result{Hosts: []vascan.HostResult{{Target: "192.0.2.188", Status: "completed", Services: []vacheck.Asset{{IP: "192.0.2.188", Port: 443, Service: "https", Version: "2.4", CPE: []string{"cpe:/a:example:service:2.4"}}}}}}}
	}
	for range 2 {
		nvdState.Lock()
		nvdState.last = nvdState.last.Add(-10_000_000_000)
		nvdState.Unlock()
		record := makeRecord()
		s.vaAutoReviewFrom(context.Background(), &record, remote.URL, remote.Client())
		if record.CVEAuto == nil || record.CVEAuto.Status != "completed" || record.CVEAuto.Candidates != 1 || len(record.CVEChecks) != 1 || record.CVEChecks[0].Status != "possible" || !record.CVEChecks[0].Automatic {
			b, _ := json.Marshal(record)
			t.Fatalf("auto review: %s", b)
		}
	}
	var count int
	if err := s.m.pg.QueryRow(`SELECT count(*) FROM findings WHERE task_id=$1 AND worker='va-cve:nvd' AND name LIKE 'CVE-2026-12345%' AND status='pending'`, taskID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("same host/CVE should have one pending finding, got %s", strconv.Itoa(count))
	}
}
