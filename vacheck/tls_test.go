package vacheck_test

import (
	"os"
	"strings"
	"testing"

	"github.com/MTheux/it4us-va/vacheck"
)

func TestParseTLS_WeakProtocolsAndCiphers(t *testing.T) {
	raw, err := os.ReadFile("testdata/testssl-weak.json")
	if err != nil {
		t.Fatal(err)
	}
	got, err := vacheck.ParseTLS(raw)
	if err != nil {
		t.Fatal(err)
	}
	var sslv3, rc4 bool
	for _, c := range got {
		if vacheck.NormalizeSeverity(c.Severity) == "" {
			t.Fatalf("severity invalida: %q", c.Severity)
		}
		if strings.Contains(c.Evidence, "SSLv3") {
			sslv3 = true
		}
		if strings.Contains(c.Evidence, "RC4") {
			rc4 = true
		}
	}
	if !sslv3 || !rc4 {
		t.Fatalf("esperava candidates para SSLv3 e RC4 (sslv3=%v rc4=%v)", sslv3, rc4)
	}
}

func TestParseTLS_StrongNoCandidates(t *testing.T) {
	raw, err := os.ReadFile("testdata/testssl-strong.json")
	if err != nil {
		t.Fatal(err)
	}
	got, err := vacheck.ParseTLS(raw)
	if err != nil {
		t.Fatalf("config forte nao deveria dar erro: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("config forte deveria gerar 0 candidates, veio %d", len(got))
	}
}

func TestParseTLS_MalformedNoPanic(t *testing.T) {
	_, err := vacheck.ParseTLS([]byte(`[{"id":"SSLv3",`))
	if err == nil {
		t.Fatal("esperava erro em JSON malformado")
	}
}
