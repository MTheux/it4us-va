package vacheck_test

import (
	"os"
	"testing"

	"github.com/MTheux/it4us-va/vacheck"
)

func TestParseADHygiene_FindsStaleKrbtgtSidHistorySprawl(t *testing.T) {
	raw, err := os.ReadFile("testdata/ad-hygiene.json")
	if err != nil {
		t.Fatal(err)
	}
	got, err := vacheck.ParseADHygiene(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("esperava 3 achados (krbtgt velho + sIDHistory + admin sprawl), veio %d", len(got))
	}
	for _, c := range got {
		if vacheck.NormalizeSeverity(c.Severity) == "" {
			t.Fatalf("severity invalida: %q (check %q)", c.Severity, c.Check)
		}
	}
}

func TestParseADHygiene_CleanNoCandidates(t *testing.T) {
	raw, err := os.ReadFile("testdata/ad-clean.json")
	if err != nil {
		t.Fatal(err)
	}
	got, err := vacheck.ParseADHygiene(raw)
	if err != nil {
		t.Fatalf("AD higiênico nao deveria dar erro: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("AD higiênico deveria gerar 0 candidates, veio %d", len(got))
	}
}

func TestParseADHygiene_MalformedNoPanic(t *testing.T) {
	if _, err := vacheck.ParseADHygiene([]byte("{nope")); err == nil {
		t.Fatal("esperava erro em JSON malformado")
	}
}
