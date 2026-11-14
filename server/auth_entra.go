package server

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

const (
	entraStateCookie = "guard4us_oidc_state"
	entraHintCookie  = "guard4us_sso"
	appTokenCookie   = "it4us_token"
)

var uuidPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type entraConfig struct {
	TenantID     string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	RequiredRole string
}

type entraPending struct {
	Nonce    string
	Verifier string
	Expires  time.Time
}

type entraIdentity struct {
	TenantID string   `json:"tid"`
	ObjectID string   `json:"oid"`
	Name     string   `json:"name"`
	Email    string   `json:"preferred_username"`
	Nonce    string   `json:"nonce"`
	Roles    []string `json:"roles"`
}

func configuredEntra() (entraConfig, bool) {
	c := entraConfig{
		TenantID:     strings.TrimSpace(os.Getenv("GUARD4US_ENTRA_TENANT_ID")),
		ClientID:     strings.TrimSpace(os.Getenv("GUARD4US_ENTRA_CLIENT_ID")),
		ClientSecret: strings.TrimSpace(os.Getenv("GUARD4US_ENTRA_CLIENT_SECRET")),
		RedirectURL:  strings.TrimSpace(os.Getenv("GUARD4US_ENTRA_REDIRECT_URL")),
		RequiredRole: strings.TrimSpace(os.Getenv("GUARD4US_ENTRA_REQUIRED_ROLE")),
	}
	if c.RequiredRole == "" {
		c.RequiredRole = "Guard4US.Access"
	}
	u, err := url.Parse(c.RedirectURL)
	if err != nil || !uuidPattern.MatchString(c.TenantID) || !uuidPattern.MatchString(c.ClientID) || c.ClientSecret == "" ||
		u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "/api/auth/entra/callback" || u.RawQuery != "" || u.Fragment != "" {
		return entraConfig{}, false
	}
	return c, true
}

func randomURLToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (s *Server) entraOAuth(ctx context.Context, c entraConfig) (*oidc.Provider, oauth2.Config, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	provider, err := oidc.NewProvider(ctx, "https://login.microsoftonline.com/"+c.TenantID+"/v2.0")
	if err != nil {
		return nil, oauth2.Config{}, err
	}
	return provider, oauth2.Config{
		ClientID: c.ClientID, ClientSecret: c.ClientSecret, Endpoint: provider.Endpoint(),
		RedirectURL: c.RedirectURL, Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
	}, nil
}

func validEntraIdentity(id entraIdentity, c entraConfig, nonce string) bool {
	if !hmac.Equal([]byte(id.Nonce), []byte(nonce)) || !strings.EqualFold(id.TenantID, c.TenantID) ||
		!uuidPattern.MatchString(id.ObjectID) {
		return false
	}
	for _, role := range id.Roles {
		if role == c.RequiredRole {
			return true
		}
	}
	return false
}

func (s *Server) authEntraStart(w http.ResponseWriter, r *http.Request) {
	c, ok := configuredEntra()
	if !ok {
		writeErr(w, 503, "Microsoft SSO is not configured")
		return
	}
	state, err := randomURLToken()
	if err != nil {
		writeErr(w, 500, "SSO initialization failed")
		return
	}
	nonce, err := randomURLToken()
	if err != nil {
		writeErr(w, 500, "SSO initialization failed")
		return
	}
	provider, oauth, err := s.entraOAuth(r.Context(), c)
	if err != nil || provider == nil {
		writeErr(w, 503, "Microsoft SSO is temporarily unavailable")
		return
	}
	verifier := oauth2.GenerateVerifier()
	s.entraMu.Lock()
	if s.entraStates == nil {
		s.entraStates = make(map[string]entraPending)
	}
	for key, pending := range s.entraStates {
		if time.Now().After(pending.Expires) {
			delete(s.entraStates, key)
		}
	}
	if len(s.entraStates) >= 1024 {
		s.entraMu.Unlock()
		writeErr(w, 429, "Too many pending SSO logins")
		return
	}
	s.entraStates[state] = entraPending{Nonce: nonce, Verifier: verifier, Expires: time.Now().Add(5 * time.Minute)}
	s.entraMu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: entraStateCookie, Value: state, Path: "/api/auth/entra/", MaxAge: 300, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}

func (s *Server) consumeEntraState(state string) (entraPending, bool) {
	s.entraMu.Lock()
	defer s.entraMu.Unlock()
	pending, ok := s.entraStates[state]
	delete(s.entraStates, state)
	return pending, ok && time.Now().Before(pending.Expires)
}

func (s *Server) authEntraCallback(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: entraStateCookie, Path: "/api/auth/entra/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	w.Header().Set("Cache-Control", "no-store")
	c, ok := configuredEntra()
	if !ok {
		writeErr(w, 503, "Microsoft SSO is not configured")
		return
	}
	state := r.URL.Query().Get("state")
	cookie, err := r.Cookie(entraStateCookie)
	if err != nil || state == "" || !hmac.Equal([]byte(state), []byte(cookie.Value)) {
		writeErr(w, 401, "Invalid SSO state")
		return
	}
	pending, valid := s.consumeEntraState(state)
	if !valid {
		writeErr(w, 401, "Expired SSO state")
		return
	}
	if r.URL.Query().Get("error") != "" || r.URL.Query().Get("code") == "" {
		http.Redirect(w, r, "/login?sso_error=1", http.StatusSeeOther)
		return
	}
	provider, oauth, err := s.entraOAuth(r.Context(), c)
	if err != nil {
		writeErr(w, 503, "Microsoft SSO is temporarily unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	token, err := oauth.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(pending.Verifier))
	if err != nil {
		writeErr(w, 401, "SSO code exchange failed")
		return
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		writeErr(w, 401, "SSO identity token missing")
		return
	}
	verified, err := provider.Verifier(&oidc.Config{ClientID: c.ClientID}).Verify(ctx, rawIDToken)
	if err != nil {
		writeErr(w, 401, "SSO identity verification failed")
		return
	}
	var identity entraIdentity
	if err := verified.Claims(&identity); err != nil || !validEntraIdentity(identity, c, pending.Nonce) {
		http.Redirect(w, r, "/login?sso_error=access", http.StatusSeeOther)
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	name := strings.TrimSpace(identity.Name)
	if name == "" {
		name = strings.TrimSpace(identity.Email)
	}
	if name == "" {
		name = "Microsoft user"
	}
	var userID int64
	var displayName, email string
	err = pg.QueryRowContext(ctx, `INSERT INTO auth_users(tenant_id,object_id,display_name,email)
		VALUES ($1,$2,$3,$4) ON CONFLICT (tenant_id,object_id) DO UPDATE SET
		display_name=EXCLUDED.display_name,email=EXCLUDED.email,last_login_at=now()
		WHERE auth_users.disabled=false RETURNING id,display_name,email`,
		identity.TenantID, identity.ObjectID, name, strings.TrimSpace(identity.Email)).Scan(&userID, &displayName, &email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Redirect(w, r, "/login?sso_error=disabled", http.StatusSeeOther)
		} else {
			writeErr(w, 503, errDataSourceUnavailable)
		}
		return
	}
	claims := roleClaims{Role: "admin", Provider: "entra", UserID: fmt.Sprint(userID), Name: displayName, Email: email,
		TenantID: identity.TenantID, ObjectID: identity.ObjectID, RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "entra:" + identity.TenantID + ":" + identity.ObjectID,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)), IssuedAt: jwt.NewNumericDate(time.Now()),
		}}
	session, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.jwtKey)
	if err != nil {
		writeErr(w, 500, "SSO session creation failed")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: appTokenCookie, Value: session, Path: "/", MaxAge: 3600, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	http.SetCookie(w, &http.Cookie{Name: entraHintCookie, Value: "1", Path: "/", MaxAge: 3600, Secure: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, "/function/va-runs", http.StatusSeeOther)
}

func (s *Server) authLogout(w http.ResponseWriter, r *http.Request) {
	for _, name := range []string{appTokenCookie, entraHintCookie} {
		http.SetCookie(w, &http.Cookie{Name: name, Path: "/", MaxAge: -1, HttpOnly: name == appTokenCookie, Secure: true, SameSite: http.SameSiteLaxMode})
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) entraUserActive(ctx context.Context, c *roleClaims) (bool, error) {
	config, enabled := configuredEntra()
	if !enabled || !strings.EqualFold(c.TenantID, config.TenantID) {
		return false, nil
	}
	pg := s.m.pg
	if pg == nil {
		return false, errors.New("database unavailable")
	}
	var active bool
	err := pg.QueryRowContext(ctx, `SELECT NOT disabled FROM auth_users WHERE id=$1 AND tenant_id=$2 AND object_id=$3`, c.UserID, c.TenantID, c.ObjectID).Scan(&active)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return active, err
}
