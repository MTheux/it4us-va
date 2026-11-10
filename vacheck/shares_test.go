package vacheck_test

import (
	"os"
	"strings"
	"testing"

	"github.com/MTheux/it4us-va/db"
	"github.com/MTheux/it4us-va/vacheck"
)

func TestParseShares_FindsWorldWritable(t *testing.T) {
	raw, err := os.ReadFile("testdata/smb-shares.json")
	if err != nil {
		t.Fatal(err)
	}
	got, err := vacheck.ParseShares(raw)
	if err != nil {
		t.Fatal(err)
	}
	var highWritable bool
	for _, c := range got {
		if vacheck.NormalizeSeverity(c.Severity) == "" {
			t.Fatalf("severity invalida: %q", c.Severity)
		}
		if c.Severity == db.SeverityHigh && strings.Contains(c.Evidence, "PUBLIC$") {
			highWritable = true
		}
	}
	if !highWritable {
		t.Fatal("esperava achado high para share anônimo gravável PUBLIC$")
	}
}

func TestParseShares_NoFileContent(t *testing.T) {
	raw, _ := os.ReadFile("testdata/smb-shares.json")
	got, err := vacheck.ParseShares(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range got {
		blob := c.Evidence + " " + c.Summary + " " + c.Title
		if strings.Contains(blob, "AKIAZ3XAMPLESECRETval") || strings.Contains(blob, "AWS_SECRET") {
			t.Fatalf("VAZAMENTO: candidate %q contem conteudo de arquivo: %q", c.Check, blob)
		}
	}
}

func TestParseShares_MalformedNoPanic(t *testing.T) {
	if _, err := vacheck.ParseShares([]byte("{nope")); err == nil {
		t.Fatal("esperava erro em JSON malformado")
	}
}
