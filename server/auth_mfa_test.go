package server

import (
	"strings"
	"testing"
	"time"
)

func TestTOTPRFC6238SHA1(t *testing.T) {
	// RFC 6238 Appendix B: SHA-1, T=59s, eight digits 94287082.
	// Guard4US uses the final six digits for authenticator compatibility.
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	code, err := totpCode(secret, 59/30)
	if err != nil || code != "287082" {
		t.Fatalf("TOTP vector: got %q, err %v", code, err)
	}
	if _, ok := matchingTOTPStep(secret, code, time.Unix(59, 0)); !ok {
		t.Fatal("valid TOTP code rejected")
	}
	if _, ok := matchingTOTPStep(secret, code, time.Unix(119, 0)); ok {
		t.Fatal("expired TOTP code accepted")
	}
}

func TestMFASecretEncryptionAndSetupToken(t *testing.T) {
	s := &Server{jwtKey: []byte("0123456789abcdef0123456789abcdef")}
	secret, err := newMFASecret()
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := s.encryptMFASecret(secret)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(encrypted, secret) {
		t.Fatal("MFA secret persisted in plaintext")
	}
	if got, err := s.decryptMFASecret(encrypted); err != nil || got != secret {
		t.Fatalf("decrypt: %q, %v", got, err)
	}
	position := len(encrypted) / 2
	last := encrypted[position]
	other := byte('A')
	if last == other {
		other = 'B'
	}
	if _, err := s.decryptMFASecret(encrypted[:position] + string(other) + encrypted[position+1:]); err == nil {
		t.Fatal("tampered MFA ciphertext accepted")
	}
	token, err := s.signMFASetupToken("password-hash-v1")
	if err != nil {
		t.Fatal(err)
	}
	if !s.verifyMFASetupToken(token, "password-hash-v1") || s.verifyMFASetupToken(token, "password-hash-v2") {
		t.Fatal("MFA setup token did not bind to password hash")
	}
	if role, ok := tokenRole(token, s.jwtKey); ok || role != "" {
		t.Fatal("MFA setup token granted a full session")
	}
}
