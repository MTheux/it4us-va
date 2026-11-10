package vacheck_test

import (
	"os"
	"strings"
	"testing"

	"github.com/MTheux/it4us-va/vacheck"
)

func TestParseSQLExposure_FindsSaAndLinked(t *testing.T) {
	raw, err := os.ReadFile("testdata/sql-exposure.json")
	if err != nil {
		t.Fatal(err)
	}
	got, err := vacheck.ParseSQLExposure(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) < 2 {
		t.Fatalf("esperava >=2 candidates (sa + linked servers), veio %d", len(got))
	}
	for _, c := range got {
		if vacheck.NormalizeSeverity(c.Severity) == "" {
			t.Fatalf("severity invalida: %q (check %q)", c.Severity, c.Check)
		}
	}
}

func TestParseSQLExposure_NoPII(t *testing.T) {
	raw, _ := os.ReadFile("testdata/sql-exposure.json")
	got, err := vacheck.ParseSQLExposure(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range got {
		blob := c.Evidence + " " + c.Summary + " " + c.Title
		if strings.Contains(blob, "111.444.777-35") || strings.Contains(blob, "Fulano") {
			t.Fatalf("VAZAMENTO PII: candidate %q contem valor de linha de dados: %q", c.Check, blob)
		}
	}
}
