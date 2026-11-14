package server

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/MTheux/it4us-va/db"
	"github.com/golang-jwt/jwt/v5"
)

const (
	authMFASecretKey   = "auth.mfa_secret"
	authMFAPendingKey  = "auth.mfa_pending"
	authMFALastStepKey = "auth.mfa_last_step"
	mfaStepSeconds     = int64(30)
)

type authFailure struct {
	count   int
	blocked time.Time
}

func authAttemptKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) authAttemptAllowed(key string) bool {
	s.authMu.Lock()
	defer s.authMu.Unlock()
	f := s.authFails[key]
	return !time.Now().Before(f.blocked)
}

func (s *Server) authAttemptFailed(key string) {
	s.authMu.Lock()
	defer s.authMu.Unlock()
	if s.authFails == nil {
		s.authFails = make(map[string]authFailure)
	}
	f := s.authFails[key]
	if !f.blocked.IsZero() && time.Now().After(f.blocked) {
		f = authFailure{}
	}
	f.count++
	if f.count >= 5 {
		f.blocked = time.Now().Add(5 * time.Minute)
	}
	s.authFails[key] = f
}

func (s *Server) authAttemptSucceeded(key string) {
	s.authMu.Lock()
	delete(s.authFails, key)
	s.authMu.Unlock()
}

func (s *Server) passwordProof(hash string) string {
	mac := hmac.New(sha256.New, s.jwtKey)
	_, _ = mac.Write([]byte("guard4us-mfa-password:" + hash))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *Server) signMFASetupToken(hash string) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, roleClaims{Purpose: "mfa-enroll", PasswordProof: s.passwordProof(hash), RegisteredClaims: jwt.RegisteredClaims{
		Subject: "IT4US VA", ExpiresAt: jwt.NewNumericDate(time.Now().Add(10 * time.Minute)), IssuedAt: jwt.NewNumericDate(time.Now()),
	}}).SignedString(s.jwtKey)
}

func (s *Server) verifyMFASetupToken(token, hash string) bool {
	claims := &roleClaims{}
	t, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, errors.New("unexpected signing method")
		}
		return s.jwtKey, nil
	})
	return err == nil && t.Valid && claims.Subject == "IT4US VA" && claims.Purpose == "mfa-enroll" && !claims.MFA &&
		hmac.Equal([]byte(claims.PasswordProof), []byte(s.passwordProof(hash)))
}

func (s *Server) mfaCipher() (cipher.AEAD, error) {
	key := sha256.Sum256(append([]byte("guard4us-mfa-key-v1:"), s.jwtKey...))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (s *Server) encryptMFASecret(secret string) (string, error) {
	gcm, err := s.mfaCipher()
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, []byte(secret), []byte("guard4us-mfa-secret-v1"))
	return "v1:" + base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (s *Server) decryptMFASecret(value string) (string, error) {
	if !strings.HasPrefix(value, "v1:") {
		return "", errors.New("unsupported MFA secret format")
	}
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, "v1:"))
	if err != nil {
		return "", err
	}
	gcm, err := s.mfaCipher()
	if err != nil {
		return "", err
	}
	if len(data) < gcm.NonceSize() {
		return "", errors.New("invalid MFA secret")
	}
	plain, err := gcm.Open(nil, data[:gcm.NonceSize()], data[gcm.NonceSize():], []byte("guard4us-mfa-secret-v1"))
	return string(plain), err
}

func newMFASecret() (string, error) {
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf), nil
}

func totpCode(secret string, step int64) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil || len(key) < 16 {
		return "", errors.New("invalid TOTP secret")
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := int(sum[len(sum)-1] & 0x0f)
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1000000), nil
}

func matchingTOTPStep(secret, code string, now time.Time) (int64, bool) {
	if len(code) != 6 {
		return 0, false
	}
	for _, ch := range code {
		if ch < '0' || ch > '9' {
			return 0, false
		}
	}
	step := now.Unix() / mfaStepSeconds
	for _, candidate := range []int64{step - 1, step, step + 1} {
		want, err := totpCode(secret, candidate)
		if err == nil && hmac.Equal([]byte(want), []byte(code)) {
			return candidate, true
		}
	}
	return 0, false
}

func (s *Server) recoveryKey(code string) string {
	mac := hmac.New(sha256.New, s.jwtKey)
	_, _ = mac.Write([]byte("guard4us-recovery:" + code))
	return "auth.mfa_recovery." + hex.EncodeToString(mac.Sum(nil))
}

func (s *Server) verifyMFALogin(pg *db.DB, encrypted, input string) (bool, error) {
	code := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(input), "-", ""), " ", ""))
	secret, err := s.decryptMFASecret(encrypted)
	if err != nil {
		return false, err
	}
	if step, matched := matchingTOTPStep(secret, code, time.Now()); matched {
		result, err := pg.Exec(`INSERT INTO settings(key,value) VALUES ($1,$2)
			ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=now()
			WHERE settings.value::bigint < EXCLUDED.value::bigint`, authMFALastStepKey, fmt.Sprint(step))
		if err != nil {
			return false, err
		}
		n, err := result.RowsAffected()
		return n == 1, err
	}
	if len(code) != 16 {
		return false, nil
	}
	for _, ch := range code {
		if !((ch >= 'A' && ch <= 'Z') || (ch >= '2' && ch <= '7')) {
			return false, nil
		}
	}
	result, err := pg.Exec(`DELETE FROM settings WHERE key=$1`, s.recoveryKey(code))
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	return n == 1, err
}

func (s *Server) mfaSetupAuthorized(pg *db.DB, token string) bool {
	hash, ok, err := pg.GetSetting(authPassKey)
	return err == nil && ok && hash != "" && s.verifyMFASetupToken(token, hash)
}

// Enrollment returns a provisioning URI only after successful password verification.
func (s *Server) authMFASetup(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req struct {
		SetupToken string `json:"setup_token"`
	}
	if decode(r, &req) != nil || !s.mfaSetupAuthorized(pg, req.SetupToken) {
		writeErr(w, 401, "MFA setup authorization required")
		return
	}
	if existing, _, err := pg.GetSetting(authMFASecretKey); err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	} else if existing != "" {
		writeErr(w, 409, "MFA already enabled")
		return
	}
	pending, _, err := pg.GetSetting(authMFAPendingKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if pending == "" {
		secret, err := newMFASecret()
		if err != nil {
			writeErr(w, 500, "MFA setup failed")
			return
		}
		pending, err = s.encryptMFASecret(secret)
		if err != nil {
			writeErr(w, 500, "MFA setup failed")
			return
		}
		inserted, err := pg.InsertSettingIfAbsent(authMFAPendingKey, pending)
		if err != nil {
			writeErr(w, 503, errDataSourceUnavailable)
			return
		}
		if !inserted {
			pending, _, err = pg.GetSetting(authMFAPendingKey)
			if err != nil {
				writeErr(w, 503, errDataSourceUnavailable)
				return
			}
		}
	}
	secret, err := s.decryptMFASecret(pending)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	uri := "otpauth://totp/" + url.PathEscape("Guard4US:IT4US VA") + "?secret=" + secret + "&issuer=Guard4US&algorithm=SHA1&digits=6&period=30"
	writeJSON(w, 200, map[string]any{"secret": secret, "uri": uri})
}

func (s *Server) authMFAConfirm(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req struct {
		SetupToken string `json:"setup_token"`
		Code       string `json:"code"`
	}
	if decode(r, &req) != nil || !s.mfaSetupAuthorized(pg, req.SetupToken) {
		writeErr(w, 401, "MFA setup authorization required")
		return
	}
	key := authAttemptKey(r)
	if !s.authAttemptAllowed(key) {
		writeErr(w, 429, "Too many attempts; retry later")
		return
	}
	pending, _, err := pg.GetSetting(authMFAPendingKey)
	if err != nil || pending == "" {
		writeErr(w, 409, "MFA setup unavailable; restart login")
		return
	}
	secret, err := s.decryptMFASecret(pending)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	step, valid := matchingTOTPStep(secret, strings.TrimSpace(req.Code), time.Now())
	if !valid {
		s.authAttemptFailed(key)
		writeErr(w, 401, "Invalid MFA code")
		return
	}
	const count = 8
	codes := make([]string, count)
	for i := range codes {
		bytes := make([]byte, 10)
		if _, err := rand.Read(bytes); err != nil {
			writeErr(w, 500, "MFA setup failed")
			return
		}
		codes[i] = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(bytes)
	}
	tx, err := pg.BeginTx(r.Context(), nil)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(r.Context(), `INSERT INTO settings(key,value) VALUES ($1,$2) ON CONFLICT (key) DO NOTHING`, authMFASecretKey, pending)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		writeErr(w, 409, "MFA already enabled")
		return
	}
	if _, err := tx.ExecContext(r.Context(), `INSERT INTO settings(key,value) VALUES ($1,$2) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=now()`, authMFALastStepKey, fmt.Sprint(step)); err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	for _, code := range codes {
		if _, err := tx.ExecContext(r.Context(), `INSERT INTO settings(key,value) VALUES ($1,'unused')`, s.recoveryKey(code)); err != nil {
			writeErr(w, 503, errDataSourceUnavailable)
			return
		}
	}
	if _, err := tx.ExecContext(r.Context(), `DELETE FROM settings WHERE key=$1`, authMFAPendingKey); err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if err := tx.Commit(); err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	s.authAttemptSucceeded(key)
	tok, err := signJWT(s.jwtKey)
	if err != nil {
		writeErr(w, 500, "token generation failed")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"token": tok, "recovery_codes": codes})
}
