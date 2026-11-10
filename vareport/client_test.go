package vareport

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreateFindingPostsToDesignEndpoint(t *testing.T) {
	var gotPath, gotAuth string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"f1"}`))
	}))
	defer srv.Close()

	c := NewHTTPClient(Config{BaseURL: srv.URL, Token: "tok", DesignID: "d1"})
	if err := c.CreateFinding(context.Background(), "p1", FindingPayload{Title: "t", Severity: "high", Summary: "s"}); err != nil {
		t.Fatalf("CreateFinding error: %v", err)
	}
	if gotPath != "/api/v1/pentestprojects/p1/findings/" {
		t.Errorf("path=%q", gotPath)
	}
	if gotAuth != "Bearer tok" {
		t.Errorf("auth=%q", gotAuth)
	}
	var payload struct {
		Data     map[string]any `json:"data"`
		Language string         `json:"language"`
	}
	if err := json.Unmarshal(gotBody, &payload); err != nil {
		t.Fatalf("body not json: %v (%s)", err, gotBody)
	}
	if payload.Data["title"] != "t" || payload.Data["severity"] != "high" {
		t.Errorf("data=%v", payload.Data)
	}
	if payload.Language != "pt-PT" {
		t.Errorf("language=%q want pt-PT", payload.Language)
	}
}

func TestCreateProjectReturnsID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/pentestprojects/" {
			t.Errorf("path=%q", r.URL.Path)
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["project_type"] != "d1" {
			t.Errorf("project_type=%v want d1", body["project_type"])
		}
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"id":"proj-123"}`))
	}))
	defer srv.Close()
	c := NewHTTPClient(Config{BaseURL: srv.URL, Token: "tok", DesignID: "d1"})
	id, err := c.CreateProject(context.Background(), "VA Teste")
	if err != nil || id != "proj-123" {
		t.Fatalf("id=%q err=%v", id, err)
	}
}

func TestRenderUsesGETAndParsesMessages(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method=%q want GET", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/check/") {
			t.Errorf("path=%q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"messages":[{"level":"warning","message":"Empty field","location":{"id":"Projeto","path":"start_date"}},{"level":"warning","message":"No anchor #x"}]}`))
	}))
	defer srv.Close()
	c := NewHTTPClient(Config{BaseURL: srv.URL, Token: "tok"})
	res, err := c.Render(context.Background(), "p1")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Messages) != 2 {
		t.Fatalf("messages=%v", res.Messages)
	}
	// Empty field is benign; only the anchor defect blocks.
	block := res.Blocking()
	if len(block) != 1 || !strings.Contains(block[0].Message, "No anchor") {
		t.Errorf("blocking=%v", block)
	}
}

func TestUploadImageReturnsName(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/images/") {
			t.Errorf("path=%q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"name":"img-abc.png"}`))
	}))
	defer srv.Close()
	c := NewHTTPClient(Config{BaseURL: srv.URL, Token: "tok"})
	ref, err := c.UploadImage(context.Background(), "p1", "shot.png", []byte("PNGDATA"))
	if err != nil || ref != "img-abc.png" {
		t.Fatalf("ref=%q err=%v", ref, err)
	}
}

func TestExportPDFWritesFile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pdf")
		_, _ = w.Write([]byte("%PDF-1.7 fake"))
	}))
	defer srv.Close()
	dest := filepath.Join(t.TempDir(), "laudo.pdf")
	c := NewHTTPClient(Config{BaseURL: srv.URL, Token: "tok"})
	if err := c.ExportPDF(context.Background(), "p1", dest); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(dest)
	if err != nil || !strings.HasPrefix(string(b), "%PDF") {
		t.Fatalf("pdf not written: %v (%q)", err, b)
	}
}

func TestCreateFindingNeverSendsNullLists(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"f1"}`))
	}))
	defer srv.Close()
	c := NewHTTPClient(Config{BaseURL: srv.URL, Token: "tok"})
	// AffectedComponents e References nil (vazios).
	if err := c.CreateFinding(context.Background(), "p1", FindingPayload{Title: "t", Severity: "low"}); err != nil {
		t.Fatal(err)
	}
	var p struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(gotBody, &p); err != nil {
		t.Fatal(err)
	}
	if string(p.Data["affected_components"]) != "[]" || string(p.Data["references"]) != "[]" {
		t.Errorf("list fields não devem ser null: ac=%s refs=%s", p.Data["affected_components"], p.Data["references"])
	}
}
