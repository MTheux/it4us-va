package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testTenantID = "11111111-2222-3333-4444-555555555555"
const testClientID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
const testObjectID = "99999999-8888-7777-6666-555555555555"

func TestEntraConfigFailsClosed(t *testing.T) {
	t.Setenv("GUARD4US_ENTRA_TENANT_ID", testTenantID)
	t.Setenv("GUARD4US_ENTRA_CLIENT_ID", testClientID)
	t.Setenv("GUARD4US_ENTRA_CLIENT_SECRET", "test-only-secret")
	t.Setenv("GUARD4US_ENTRA_REDIRECT_URL", "http://example.com/api/auth/entra/callback")
	if _, ok := configuredEntra(); ok {
		t.Fatal("non-TLS redirect enabled SSO")
	}
	t.Setenv("GUARD4US_ENTRA_REDIRECT_URL", "https://guard.example.com/api/auth/entra/callback")
	c, ok := configuredEntra()
	if !ok || c.RequiredRole != "Guard4US.Access" {
		t.Fatal("valid single-tenant config rejected")
	}
	if validEntraIdentity(entraIdentity{TenantID: testTenantID, ObjectID: testObjectID, Nonce: "n", Roles: []string{"Other"}}, c, "n") {
		t.Fatal("unassigned tenant user admitted")
	}
	if validEntraIdentity(entraIdentity{TenantID: testTenantID, ObjectID: testObjectID, Nonce: "wrong", Roles: []string{c.RequiredRole}}, c, "n") {
		t.Fatal("wrong nonce admitted")
	}
	if validEntraIdentity(entraIdentity{TenantID: testClientID, ObjectID: testObjectID, Nonce: "n", Roles: []string{c.RequiredRole}}, c, "n") {
		t.Fatal("other tenant admitted")
	}
	if !validEntraIdentity(entraIdentity{TenantID: testTenantID, ObjectID: testObjectID, Nonce: "n", Roles: []string{c.RequiredRole}}, c, "n") {
		t.Fatal("assigned tenant user rejected")
	}
}

func TestEntraStateIsSingleUseAndUnconfiguredStartFails(t *testing.T) {
	s := &Server{entraStates: map[string]entraPending{"state": {Nonce: "n", Expires: time.Now().Add(time.Minute)}}}
	if _, ok := s.consumeEntraState("state"); !ok {
		t.Fatal("valid state rejected")
	}
	if _, ok := s.consumeEntraState("state"); ok {
		t.Fatal("state replay accepted")
	}
	t.Setenv("GUARD4US_ENTRA_TENANT_ID", "")
	r := httptest.NewRequest(http.MethodGet, "/api/auth/entra/start", nil)
	w := httptest.NewRecorder()
	s.authEntraStart(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured start: got %d", w.Code)
	}
}

func TestEntraSessionClaimsAreDistinctFromLocalMFA(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	claims := roleClaims{Role: "admin", Provider: "entra", UserID: "42", TenantID: testTenantID, ObjectID: testObjectID,
		RegisteredClaims: jwt.RegisteredClaims{Subject: "entra:" + testTenantID + ":" + testObjectID, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := parseSessionClaims(token, key); !ok {
		t.Fatal("signed Entra session rejected")
	}
	claims.Subject = "IT4US VA"
	forged, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
	if _, ok := parseSessionClaims(forged, key); ok {
		t.Fatal("Entra session with local subject accepted")
	}
}
