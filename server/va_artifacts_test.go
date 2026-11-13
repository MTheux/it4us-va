package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVAArtifactPathAllowlist(t *testing.T) {
	hash := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	for _, path := range []string{"plan.json", "events.jsonl", "receipt.json", "analysis-input.json", "draxen/analysis.json", "draxen/va-plan.json", "draxen/HANDOFF.md", "draxen/audit.jsonl", "hosts/" + hash + ".json", "raw/" + hash + ".xml", "vt/" + hash + ".xml"} {
		if !validVAArtifactPath(path) {
			t.Fatalf("expected allowed path: %s", path)
		}
	}
	for _, path := range []string{"../config.json", "hosts/../../config.json", "draxen/../config.json", "draxen/secret.env", "raw/not-a-hash.xml", "hosts/" + hash + ".json.sha256", "raw/" + hash + ".json", "plan.json/other"} {
		if validVAArtifactPath(path) {
			t.Fatalf("unexpected allowed path: %s", path)
		}
	}
}

func TestVAArtifactEvidenceIsPrivateAndEventsAppend(t *testing.T) {
	s := &Server{m: &Manager{dir: t.TempDir()}}
	id := "0123456789abcdef01234567"
	if err := s.vaSaveArtifact(id, "plan.json", []byte(`{"target":"127.0.0.1"}`)); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(s.vaArtifactDir(id), "plan.json"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("artifact mode: %v %v", info, err)
	}
	s.vaAppendEvent(id, vaEvent{Stage: "authorization", Status: "completed"})
	s.vaAppendEvent(id, vaEvent{Stage: "campaign", Status: "started"})
	body, err := os.ReadFile(filepath.Join(s.vaArtifactDir(id), "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 events, got %d", len(lines))
	}
	for _, line := range lines {
		var event vaEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil || event.At.IsZero() {
			t.Fatalf("invalid event: %v", err)
		}
	}
}
