package server

import (
	"strings"
	"testing"
	"time"

	"github.com/MTheux/it4us-va/vascan"
)

func TestVAChatRunBelongsToTask(t *testing.T) {
	s := &Server{m: &Manager{dir: t.TempDir()}}
	id := strings.Repeat("a", 24)
	record := vaRunRecord{
		ID: id, Campaign: vascan.Campaign{TaskID: 17},
		Status: "completed", CreatedAt: time.Now().UTC(),
	}
	if err := s.vaWriteRecord(record); err != nil {
		t.Fatal(err)
	}
	if _, found, err := s.vaChatRun("18", id); err == nil || found {
		t.Fatalf("cross-task VA receipt was accepted: found=%v err=%v", found, err)
	}
	if got, found, err := s.vaChatRun("17", id); err != nil || !found || got.ID != id {
		t.Fatalf("own VA receipt missing: found=%v err=%v got=%q", found, err, got.ID)
	}
	if got, found, err := s.vaChatRun("17", ""); err != nil || !found || got.ID != id {
		t.Fatalf("latest own VA receipt missing: found=%v err=%v got=%q", found, err, got.ID)
	}
}
