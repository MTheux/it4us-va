package server

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const (
	jwtKeyFilename = "jwt.key"
	authPassKey    = "auth.password_hash"
	socPassKey     = "auth.soc_password_hash"
	jwtTTL         = 7 * 24 * time.Hour
	keyChars       = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	// The lower bound matches the setup page's frontend validation — validation that
	// lives only in the frontend is as good as none: hitting the API directly bypasses
	// it. The upper bound is bcrypt's hard limit: past 72 bytes GenerateFromPassword returns ErrPasswordTooLong; rejecting early beats a cryptic "password encryption failed".
	minPasswordRunes = 8
	maxPasswordBytes = 72
)

// errDataSourceUnavailable is the uniform reply when a password-related read fails.
// These handlers must never mistake a failed read for "not set": authInit once let an
// unauthenticated request through on a database error, overwriting the admin password.
const errDataSourceUnavailable = "Data source temporarily unavailable, please retry later"

// validatePassword returns an empty string when passing, otherwise a reason ready to show the user.
func validatePassword(pw string) string {
	if utf8.RuneCountInString(pw) < minPasswordRunes {
		return fmt.Sprintf("Password must be at least %d characters", minPasswordRunes)
	}
	if len(pw) > maxPasswordBytes {
		return fmt.Sprintf("Password must not exceed %d bytes", maxPasswordBytes)
	}
	return ""
}

// loadOrCreateJWTKey reads the 32-byte signing key from keyDir/jwt.key. keyDir is
// the project base dir (next to the executable), NOT the browsable workspace root
// (dataDir) — the signing key must never be listable/downloadable via the file
// manager. Legacy installs kept it at dataDir/jwt.key; if present there and not yet
// at the new location, it is migrated (key preserved, so sessions stay valid) and
// the old file removed so it disappears from the workspace. On first run a random
// key is generated and persisted.
func loadOrCreateJWTKey(keyDir, dataDir string) ([]byte, error) {
	path := filepath.Join(keyDir, jwtKeyFilename)
	// one-time migration out of the old in-workspace location.
	if legacy := filepath.Join(dataDir, jwtKeyFilename); legacy != path {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			if data, rerr := os.ReadFile(legacy); rerr == nil {
				if werr := os.WriteFile(path, data, 0o600); werr == nil {
					_ = os.Remove(legacy)
					log.Printf("[auth] JWT key migrated from %s to %s (moved out of the browsable workspace)", legacy, path)
				}
			}
		}
	}
	if data, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(data))) >= 32 {
		return []byte(strings.TrimSpace(string(data))), nil
	}
	buf := make([]byte, 32)
	for i := range buf {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(keyChars))))
		if err != nil {
			return nil, fmt.Errorf("generate jwt key: %w", err)
		}
		buf[i] = keyChars[n.Int64()]
	}
	if err := os.WriteFile(path, buf, 0600); err != nil {
		return nil, fmt.Errorf("write jwt key: %w", err)
	}
	log.Printf("[auth] new JWT key written to %s", path)
	return buf, nil
}

// signJWT issues a 7-day HS256 token for user IT4US VA.
func signJWT(key []byte) (string, error) {
	return signRoleJWT(key, "admin")
}

type roleClaims struct {
	Role string `json:"role"`
	jwt.RegisteredClaims
}

func signRoleJWT(key []byte, role string) (string, error) {
	subject := "IT4US VA"
	if role == "soc" {
		subject = "IT4US SOC"
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, roleClaims{Role: role, RegisteredClaims: jwt.RegisteredClaims{
		Subject:   subject,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(jwtTTL)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}}).SignedString(key)
}

// verifyJWT returns true when tokenStr is a valid, non-expired HS256 token.
func verifyJWT(tokenStr string, key []byte) bool {
	_, ok := tokenRole(tokenStr, key)
	return ok
}

func tokenRole(tokenStr string, key []byte) (string, bool) {
	claims := &roleClaims{}
	t, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return key, nil
	})
	if err != nil || !t.Valid {
		return "", false
	}
	if claims.Role == "soc" && claims.Subject == "IT4US SOC" {
		return "soc", true
	}
	if (claims.Role == "admin" || claims.Role == "") && claims.Subject == "IT4US VA" {
		return "admin", true
	}
	return "", false
}

func socAllowedAPI(r *http.Request) bool {
	p := r.URL.Path
	for _, prefix := range []string{"/api/agents", "/api/tools", "/api/mcp", "/api/llm", "/api/settings", "/api/workspace", "/api/commands", "/api/logs", "/api/notify", "/api/visibility", "/api/audit", "/api/gc", "/api/skill-gaps"} {
		if p == prefix || strings.HasPrefix(p, prefix+"/") {
			return false
		}
	}
	if p == "/api/skills" {
		return r.Method == http.MethodGet
	}
	if strings.HasPrefix(p, "/api/skills/") {
		return false
	}
	if p == "/api/sync/scopesentry/datasource" {
		return false
	}
	if strings.Contains(p, "/credentials") {
		return false
	}
	return true
}

// extractToken reads the JWT from Authorization: Bearer header,
// it4us_token cookie, or ?token= query param (for SSE connections).
func extractToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	if c, err := r.Cookie("it4us_token"); err == nil && c.Value != "" {
		return c.Value
	}
	return r.URL.Query().Get("token")
}

// requireAuth wraps h with JWT validation.
// /api/auth/* and /api/health are exempt.
func (s *Server) requireAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if strings.HasPrefix(p, "/api/auth/") || p == "/api/health" {
			h.ServeHTTP(w, r)
			return
		}
		tok := extractToken(r)
		if tok == "" {
			writeErr(w, 401, "Unauthorized")
			return
		}
		role, valid := tokenRole(tok, s.jwtKey)
		if !valid {
			writeErr(w, 401, "token is invalid or expired")
			return
		}
		if role == "soc" && !socAllowedAPI(r) {
			writeErr(w, 403, "SOC access to administrator API is forbidden")
			return
		}
		h.ServeHTTP(w, r)
	})
}

// GET /api/auth/status — reports whether the admin password has been initialised.
// A read failure must answer 503, not initialized:false: on initialized:false the
// frontend ships the user to /setup to set a password (login/page.tsx); wrapping a
// database outage in a 200 pushes the user toward overwriting the existing password.
func (s *Server) authStatus(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	hash, _, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	writeJSON(w, 200, map[string]any{"initialized": hash != ""})
}

// POST /api/auth/init — sets the password for the first time; rejected if already set.
func (s *Server) authInit(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	existing, _, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if existing != "" {
		writeErr(w, 403, "Password is already set")
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil || req.Password == "" {
		writeErr(w, 400, "Password cannot be empty")
		return
	}
	if msg := validatePassword(req.Password); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, "Password encryption failed")
		return
	}
	// INSERT ... ON CONFLICT DO NOTHING instead of an upsert: the GetSetting above is
	// only a fast-fail path; the real "first-set-only" guarantee rests on the primary
	// key. bcrypt runs tens of milliseconds, another request may set the password meanwhile, and the read check itself can fail under an outage.
	inserted, err := pg.InsertSettingIfAbsent(authPassKey, string(hash))
	if err != nil {
		writeErr(w, 500, "Save failed: "+err.Error())
		return
	}
	if !inserted {
		writeErr(w, 403, "Password is already set")
		return
	}
	tok, err := signJWT(s.jwtKey)
	if err != nil {
		writeErr(w, 500, "token generation failed")
		return
	}
	writeJSON(w, 200, map[string]any{"token": tok})
}

// POST /api/auth/change-password — changes the admin password. Requires a valid
// token (this route is under /api/auth/* which requireAuth exempts, so the token
// is validated here) AND the current password.
func (s *Server) authChangePassword(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	if role, ok := tokenRole(extractToken(r), s.jwtKey); !ok || role != "admin" {
		writeErr(w, 401, "Unauthorized")
		return
	}
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "Invalid request format")
		return
	}
	if req.NewPassword == "" {
		writeErr(w, 400, "New password cannot be empty")
		return
	}
	if msg := validatePassword(req.NewPassword); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	hash, ok, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if !ok || hash == "" {
		writeErr(w, 403, "Password not initialized; set a password first")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.OldPassword)); err != nil {
		writeErr(w, 401, "Current password is wrong")
		return
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, "Password encryption failed")
		return
	}
	if err := pg.SetSetting(authPassKey, string(newHash)); err != nil {
		writeErr(w, 500, "Save failed: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// POST /api/auth/soc-password creates or rotates the separate SOC credential.
// The current admin password is required even when a valid admin JWT exists.
func (s *Server) authSetSOCPassword(w http.ResponseWriter, r *http.Request) {
	if role, ok := tokenRole(extractToken(r), s.jwtKey); !ok || role != "admin" {
		writeErr(w, 403, "Administrator access required")
		return
	}
	var req struct {
		AdminPassword string `json:"admin_password"`
		SOCPassword   string `json:"soc_password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "Invalid request format")
		return
	}
	if msg := validatePassword(req.SOCPassword); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	hash, ok, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if !ok || bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.AdminPassword)) != nil {
		writeErr(w, 401, "Current administrator password is wrong")
		return
	}
	socHash, err := bcrypt.GenerateFromPassword([]byte(req.SOCPassword), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, "Password encryption failed")
		return
	}
	if err := pg.SetSetting(socPassKey, string(socHash)); err != nil {
		writeErr(w, 500, "Save failed")
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// POST /api/auth/login — validates username/password and returns a JWT.
func (s *Server) authLogin(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "Invalid request format")
		return
	}
	passKey, role := authPassKey, "admin"
	if req.Username == "IT4US SOC" {
		passKey, role = socPassKey, "soc"
	} else if req.Username != "IT4US VA" {
		writeErr(w, 401, "Incorrect username or password")
		return
	}
	hash, ok, err := pg.GetSetting(passKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if !ok || hash == "" {
		writeErr(w, 403, "Password not initialized; set a password first")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)); err != nil {
		writeErr(w, 401, "Incorrect username or password")
		return
	}
	tok, err := signRoleJWT(s.jwtKey, role)
	if err != nil {
		writeErr(w, 500, "token generation failed")
		return
	}
	writeJSON(w, 200, map[string]any{"token": tok})
}
