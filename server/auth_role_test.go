package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestBothLoginsHaveAdminAccess(t *testing.T) {
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
	if role, ok := tokenRole(soc, key); !ok || role != "admin" {
		t.Fatalf("soc: %q %v", role, ok)
	}
	legacy, err := jwt.NewWithClaims(jwt.SigningMethodHS256, roleClaims{Role: "soc", RegisteredClaims: jwt.RegisteredClaims{
		Subject: "IT4US SOC", ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}}).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	if role, ok := tokenRole(legacy, key); !ok || role != "admin" {
		t.Fatalf("legacy soc: %q %v", role, ok)
	}
	if !adminPage("/system/mcp") || !adminPage("/function/workspace") || adminPage("/system/skills") {
		t.Fatal("admin page classification")
	}
}

func TestSOCMiddlewareAllowsAdministratorAPI(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	soc, _ := signRoleJWT(key, "soc")
	admin, _ := signJWT(key)
	s := &Server{jwtKey: key}
	h := s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	for _, tc := range []struct {
		token, path string
		want        int
	}{
		{soc, "/api/mcp", 204}, {soc, "/api/skills/infra-inventory/files/SKILL.md", 204},
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
