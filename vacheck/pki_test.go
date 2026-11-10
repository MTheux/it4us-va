package vacheck_test

import (
	"os"
	"strings"
	"testing"

	"github.com/MTheux/it4us-va/vacheck"
)

func TestParsePKI_WeakKeyAndSHA1(t *testing.T) {
	raw, err := os.ReadFile("testdata/cert-weak.pem")
	if err != nil {
		t.Fatal(err)
	}
	got, err := vacheck.ParsePKI(raw)
	if err != nil {
		t.Fatal(err)
	}
	var weakKey, weakSig bool
	for _, c := range got {
		if vacheck.NormalizeSeverity(c.Severity) == "" {
			t.Fatalf("severity invalida: %q", c.Severity)
		}
		ev := strings.ToLower(c.Evidence + c.Title)
		if strings.Contains(ev, "1024") {
			weakKey = true
		}
		if strings.Contains(ev, "sha1") {
			weakSig = true
		}
	}
	if !weakKey || !weakSig {
		t.Fatalf("esperava achados de chave fraca e assinatura fraca (key=%v sig=%v)", weakKey, weakSig)
	}
}

func TestParsePKI_ExpiringCert(t *testing.T) {
	raw, _ := os.ReadFile("testdata/cert-weak.pem")
	got, _ := vacheck.ParsePKI(raw)
	var expiring bool
	for _, c := range got {
		if strings.Contains(strings.ToLower(c.VulnClass), "expir") || strings.Contains(strings.ToLower(c.Title), "expir") {
			expiring = true
		}
	}
	if !expiring {
		t.Fatal("cert expira em 10 dias — esperava achado de expiração")
	}
}

func TestParseADCS_VulnerableTemplateEnum(t *testing.T) {
	raw, err := os.ReadFile("testdata/certipy-find.json")
	if err != nil {
		t.Fatal(err)
	}
	got, err := vacheck.ParseADCS(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("esperava 1 template vulnerável (ESC1), veio %d", len(got))
	}
	c := got[0]
	if vacheck.NormalizeSeverity(c.Severity) == "" {
		t.Fatalf("severity invalida: %q", c.Severity)
	}
	var tagged bool
	for _, tg := range c.Tags {
		if tg == "foresea:adcs" {
			tagged = true
		}
	}
	if !tagged {
		t.Fatal("candidate ADCS deveria ter tag foresea:adcs")
	}
	if !strings.Contains(c.Evidence, "ESC1") {
		t.Fatalf("evidence deveria citar ESC1: %q", c.Evidence)
	}
}

func TestParsePKI_GarbageNoPanic(t *testing.T) {
	if _, err := vacheck.ParsePKI([]byte("nao eh um PEM")); err == nil {
		t.Fatal("esperava erro em entrada sem PEM")
	}
	if _, err := vacheck.ParseADCS([]byte("{nope")); err == nil {
		t.Fatal("esperava erro em JSON malformado")
	}
}

func TestParseADCS_Deterministic(t *testing.T) {
	raw, err := os.ReadFile("testdata/certipy-multi.json")
	if err != nil {
		t.Fatal(err)
	}
	first, err := vacheck.ParseADCS(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 2 {
		t.Fatalf("esperava 2 templates vulneráveis, veio %d", len(first))
	}
	for i := 0; i < 30; i++ {
		got, _ := vacheck.ParseADCS(raw)
		if len(got) != len(first) {
			t.Fatalf("contagem instável na iteração %d", i)
		}
		for j := range got {
			if got[j].Evidence != first[j].Evidence || got[j].Title != first[j].Title {
				t.Fatalf("saída não-determinística na iteração %d, pos %d:\n  %q\n  %q", i, j, first[j].Evidence, got[j].Evidence)
			}
		}
	}
}
