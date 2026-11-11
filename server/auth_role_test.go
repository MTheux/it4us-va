package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSOCJWTAndRouteGates(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	admin, err := signJWT(key)
	if err != nil {
		t.Fatal(err)
	}
	soc, err := signRoleJWT(key, "soc")
	if err != nil {
		t.Fatal(err)
	}
	if role, ok := tokenRole(admin, key); !ok || role != "admin" {
		t.Fatalf("admin: %q %v", role, ok)
	}
	if role, ok := tokenRole(soc, key); !ok || role != "soc" {
		t.Fatalf("soc: %q %v", role, ok)
	}
	for _, tc := range []struct {
		method, path string
		allowed      bool
	}{
		{"GET", "/api/skills", true},
		{"POST", "/api/skills", false},
		{"GET", "/api/skills/infra-inventory/files/SKILL.md", false},
		{"GET", "/api/mcp", false},
		{"POST", "/api/llm/profiles", false},
		{"GET", "/api/workspace/read", false},
		{"POST", "/api/sync/scopesentry/datasource", false},
		{"POST", "/api/va/plan", true},
		{"GET", "/api/tasks", true},
	} {
		if got := socAllowedAPI(httptest.NewRequest(tc.method, tc.path, nil)); got != tc.allowed {
			t.Errorf("%s %s: got %v", tc.method, tc.path, got)
		}
	}
	if !adminPage("/system/mcp") || !adminPage("/function/workspace") || adminPage("/system/skills") {
		t.Fatal("admin page classification")
	}
}

func TestSOCMiddlewareDeniesAdministratorAPI(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	soc, _ := signRoleJWT(key, "soc")
	admin, _ := signJWT(key)
	s := &Server{jwtKey: key}
	h := s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	for _, tc := range []struct {
		token, path string
		want        int
	}{
		{soc, "/api/mcp", 403}, {soc, "/api/skills/infra-inventory/files/SKILL.md", 403},
		{soc, "/api/va/capabilities", 204}, {admin, "/api/mcp", 204},
	} {
		r := httptest.NewRequest("GET", tc.path, nil)
		r.Header.Set("Authorization", "Bearer "+tc.token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Errorf("%s: got %d, want %d", tc.path, w.Code, tc.want)
		}
	}
}
