package vacheck_test

import (
	"os"
	"testing"

	"github.com/MTheux/it4us-va/vacheck"
)

func TestParseNmap_ExposedServices(t *testing.T) {
	raw, err := os.ReadFile("testdata/nmap-foresea.xml")
	if err != nil {
		t.Fatal(err)
	}
	got, err := vacheck.ParseNmap(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := map[int]bool{3389: false, 445: false, 1433: false}
	for _, c := range got {
		if _, tracked := want[c.Asset.Port]; tracked {
			want[c.Asset.Port] = true
		}
		if vacheck.NormalizeSeverity(c.Severity) == "" {
			t.Fatalf("severity invalida: %q (check %q porta %d)", c.Severity, c.Check, c.Asset.Port)
		}
	}
	for port, seen := range want {
		if !seen {
			t.Fatalf("porta de risco %d nao virou candidate", port)
		}
	}
}

func TestParseNmap_CleanHostNoCandidates(t *testing.T) {
	raw, err := os.ReadFile("testdata/nmap-clean.xml")
	if err != nil {
		t.Fatal(err)
	}
	got, err := vacheck.ParseNmap(raw)
	if err != nil {
		t.Fatalf("host limpo nao deveria dar erro: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("host limpo deveria gerar 0 candidates, veio %d", len(got))
	}
}

func TestParseNmap_TruncatedNoPanic(t *testing.T) {
	raw, err := os.ReadFile("testdata/nmap-truncated.xml")
	if err != nil {
		t.Fatal(err)
	}
	_, err = vacheck.ParseNmap(raw)
	if err == nil {
		t.Fatal("esperava erro em XML truncado")
	}
}
