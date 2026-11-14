package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestMFASessionsInvalidateLegacyTokens(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	admin, err := signJWT(key)
	if err != nil {
		t.Fatal(err)
	}
	if role, ok := tokenRole(admin, key); !ok || role != "admin" {
		t.Fatalf("admin: %q %v", role, ok)
	}
	legacy, err := jwt.NewWithClaims(jwt.SigningMethodHS256, roleClaims{Role: "soc", RegisteredClaims: jwt.RegisteredClaims{
		Subject: "IT4US SOC", ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}}).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	if role, ok := tokenRole(legacy, key); ok || role != "" {
		t.Fatalf("legacy token must be rejected: %q %v", role, ok)
	}
}

func TestSOCLoginIsNoLongerAccepted(t *testing.T) {
	s := &Server{}
	r := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"username":"IT4US SOC","password":"any-password"}`))
	w := httptest.NewRecorder()
	s.authLogin(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("SOC login: got %d, want 401", w.Code)
	}
}

func TestPageIgnoresCookieFromAnotherInstance(t *testing.T) {
	s := &Server{jwtKey: []byte("0123456789abcdef0123456789abcdef")}
	r := httptest.NewRequest(http.MethodGet, "/system/mcp/", nil)
	r.AddCookie(&http.Cookie{Name: "it4us_token", Value: "token-from-other-port"})
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code == http.StatusForbidden || strings.Contains(w.Body.String(), "Administrator page") {
		t.Fatalf("cross-port cookie blocked static page: status=%d body=%q", w.Code, w.Body.String())
	}
}

func TestLegacySOCSessionCannotAccessAdministratorAPI(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	soc, err := jwt.NewWithClaims(jwt.SigningMethodHS256, roleClaims{Role: "soc", RegisteredClaims: jwt.RegisteredClaims{
		Subject: "IT4US SOC", ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}}).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	admin, _ := signJWT(key)
	s := &Server{jwtKey: key}
	h := s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	for _, tc := range []struct {
		token, path string
		want        int
	}{
		{soc, "/api/mcp", 401}, {soc, "/api/skills/infra-inventory/files/SKILL.md", 401},
		{soc, "/api/va/capabilities", 401}, {admin, "/api/mcp", 204},
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
