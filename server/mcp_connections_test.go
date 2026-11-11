package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/MTheux/it4us-va/db"
)

func TestMCPListRedactsCredentialAndUpdateKeepsIt(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	id, err := s.m.pg.SaveMCP(&db.MCPServer{
		Name: "redaction_test", Transport: "http", URL: "https://example.invalid/mcp",
		Env: json.RawMessage(`{"Authorization":"Bearer fake-test-token"}`), Enabled: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.m.pg.DeleteMCP(id) })

	list := httptest.NewRecorder()
	s.pgListMCP(list, httptest.NewRequest(http.MethodGet, "/api/mcp", nil))
	if list.Code != http.StatusOK || strings.Contains(list.Body.String(), "fake-test-token") || !strings.Contains(list.Body.String(), `"env_configured":true`) {
		t.Fatalf("credential leaked or status missing: HTTP %d", list.Code)
	}

	update := map[string]any{"id": id, "name": "redaction_test", "transport": "http", "url": "https://example.invalid/mcp", "enabled": false, "args": []any{}}
	body, _ := json.Marshal(update)
	rec := httptest.NewRecorder()
	s.pgSaveMCP(rec, httptest.NewRequest(http.MethodPost, "/api/mcp", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("update status %d: %s", rec.Code, rec.Body.String())
	}
	stored := listMCPByName(t, s.m.pg, "redaction_test")
	if !strings.Contains(string(stored.Env), "fake-test-token") {
		t.Fatal("blank edit cleared stored MCP credential")
	}
}

func TestMCPEditRediscoversWithStoredCredentialAndClearsStaleState(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	var sawCredential atomic.Bool
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer fixture-secret" {
			sawCredential.Store(true)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var rpc struct {
			ID     int    `json:"id"`
			Method string `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&rpc)
		w.Header().Set("Content-Type", "application/json")
		if rpc.ID == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		result := any(map[string]any{})
		if rpc.Method == "tools/list" {
			result = map[string]any{"tools": []map[string]any{{"name": "list_reports", "description": "fixture", "inputSchema": map[string]any{"type": "object"}}}}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": rpc.ID, "result": result})
	}))
	t.Cleanup(remote.Close)

	id, err := s.m.pg.SaveMCP(&db.MCPServer{
		Name: "edit_flow_test", Transport: "http", URL: remote.URL,
		Env: json.RawMessage(`{"Authorization":"Bearer fixture-secret"}`), Enabled: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.m.pg.DeleteMCP(id) })
	if err := s.m.pg.SaveMCPTools(id, []db.MCPTool{{Name: "obsolete"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.m.pg.UpdateMCPHealth(id, true, ""); err != nil {
		t.Fatal(err)
	}

	save := func(enabled bool, targetID int64) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{"id": targetID, "name": "edit_flow_test", "transport": "http", "url": remote.URL, "enabled": enabled, "args": []any{}})
		rec := httptest.NewRecorder()
		s.pgSaveMCP(rec, httptest.NewRequest(http.MethodPost, "/api/mcp", bytes.NewReader(body)))
		return rec
	}
	if rec := save(true, id); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"connected":true`) {
		t.Fatalf("enable response: HTTP %d %s", rec.Code, rec.Body.String())
	}
	if !sawCredential.Load() {
		t.Fatal("rediscovery omitted the stored credential")
	}
	row := listMCPByName(t, s.m.pg, "edit_flow_test")
	if row.LastConnectOK == nil || !*row.LastConnectOK || len(row.Tools) != 1 || row.Tools[0] != "mcp__edit_flow_test__list_reports" {
		t.Fatalf("old tool cache or health survived update: %+v", row)
	}
	if rec := save(false, id); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"connected":false`) {
		t.Fatalf("disable response: HTTP %d %s", rec.Code, rec.Body.String())
	}
	row = listMCPByName(t, s.m.pg, "edit_flow_test")
	if row.LastConnectOK != nil || len(row.Tools) != 0 {
		t.Fatalf("disabled connector retained active state: %+v", row)
	}
	if _, err := s.m.pg.SaveMCP(&db.MCPServer{ID: id, Name: "edit_flow_test", Transport: "http", URL: "https://other.invalid/mcp", Enabled: false, Args: json.RawMessage(`[]`)}); err != nil {
		t.Fatal(err)
	}
	row = listMCPByName(t, s.m.pg, "edit_flow_test")
	if string(row.Env) != "{}" {
		t.Fatal("old credential followed a changed MCP endpoint")
	}
	if rec := save(false, id+1000000); rec.Code != http.StatusNotFound {
		t.Fatalf("missing connector status %d", rec.Code)
	}
}

func TestMCPSaveRejectsMalformedConnection(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	for _, body := range []string{
		`{"name":"bad_url","transport":"http","url":"file:///etc/passwd","enabled":true,"args":[]}`,
		`{"name":"bad_args","transport":"stdio","command":"local","enabled":true,"args":{"unexpected":1}}`,
		`{"name":"bad_env","transport":"http","url":"https://example.invalid/mcp","enabled":false,"args":[],"env":["secret"]}`,
	} {
		rec := httptest.NewRecorder()
		s.pgSaveMCP(rec, httptest.NewRequest(http.MethodPost, "/api/mcp", strings.NewReader(body)))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("invalid MCP accepted: HTTP %d %s", rec.Code, rec.Body.String())
		}
	}
}
