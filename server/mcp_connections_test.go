package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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
