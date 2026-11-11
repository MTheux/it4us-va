package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/MTheux/it4us-va/vascan"
)

func TestRecordOnlyRejectsNonLoopbackBeforeScanner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "campaign.json")
	data := `{"name":"lab","task_id":1,"approved_by":"operator","expires_at":"` + time.Now().Add(time.Hour).UTC().Format(time.RFC3339) + `","targets":["198.51.100.7"],"ports":[443]}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := runVA([]string{"scan", "--campaign", path, "--task-id", "1", "--record-only"}); code == 0 {
		t.Fatal("record-only must reject non-loopback targets")
	}
	if _, err := vascan.LoadCampaign(path, time.Now()); err != nil {
		t.Fatalf("fixture must otherwise be a valid campaign: %v", err)
	}
}
