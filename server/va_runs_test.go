package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MTheux/it4us-va/vascan"
)

func TestVARunReceiptAndInterruptedState(t *testing.T) {
	s := &Server{m: &Manager{dir: t.TempDir()}, vaActive: map[string]*vaActiveRun{}}
	id := "00112233445566778899aabb"
	record := vaRunRecord{
		ID: id, Campaign: vascan.Campaign{Name: "lab", TaskID: 1, ApprovedBy: "soc", ExpiresAt: time.Now().Add(time.Hour)},
		Status: "running", CreatedAt: time.Now().UTC(), TotalHosts: 2,
	}
	if err := s.vaWriteRecord(record); err != nil {
		t.Fatal(err)
	}
	got, err := s.vaReadRecord(id)
	if err != nil || got.ID != id || got.TotalHosts != 2 {
		t.Fatalf("receipt=%+v err=%v", got, err)
	}
	s.vaCurrent(&got)
	if got.Status != "interrupted" {
		t.Fatalf("stale running receipt reported as %q", got.Status)
	}
	rec := httptest.NewRecorder()
	s.vaListRuns(rec, httptest.NewRequest(http.MethodGet, "/api/va/runs", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("list status=%d", rec.Code)
	}
	var list struct {
		Runs []vaRunRecord `json:"runs"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list.Runs) != 1 || list.Runs[0].Status != "interrupted" {
		t.Fatalf("list=%+v err=%v", list, err)
	}
}

func TestVAPlanRejectsUnboundedOrMalformedScopeBeforeDatabase(t *testing.T) {
	s := &Server{m: &Manager{dir: t.TempDir()}, vaActive: map[string]*vaActiveRun{}}
	for _, body := range []string{
		`{"name":"lab","task_id":1,"approved_by":"soc","expires_at":"2099-01-01T00:00:00Z","targets":["example.com"],"ports":[443]}`,
		`{"name":"lab","task_id":1,"approved_by":"soc","expires_at":"2099-01-01T00:00:00Z","targets":["10.0.0.0/8"],"ports":[443]}`,
		`{"name":"lab","task_id":1,"approved_by":"soc","expires_at":"2099-01-01T00:00:00Z","targets":["127.0.0.1"],"ports":[443]} {}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/va/plan", strings.NewReader(body))
		rec := httptest.NewRecorder()
		s.vaPlan(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
	}
}
