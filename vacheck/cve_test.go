package vacheck_test

import (
	"os"
	"testing"

	"github.com/MTheux/it4us-va/db"
	"github.com/MTheux/it4us-va/vacheck"
)

func TestCVEQueries_FromNmap(t *testing.T) {
	cands := []vacheck.Candidate{
		{Check: "nmap.service", Asset: vacheck.Asset{Service: "ms-sql-s", Port: 1433}, Evidence: "1433/tcp ms-sql-s -> Microsoft SQL Server 2016 13.00.5026"},
		{Check: "nmap.service", Asset: vacheck.Asset{Service: "ms-sql-s", Port: 1433}, Evidence: "1433/tcp ms-sql-s -> Microsoft SQL Server 2016 13.00.5026"},
	}
	qs := vacheck.CVEQueries(cands)
	if len(qs) == 0 {
		t.Fatal("esperava ao menos 1 query CVE")
	}
	if len(qs) != 1 {
		t.Fatalf("queries deveriam ser deduplicadas, veio %d: %v", len(qs), qs)
	}
}

func TestParseCVEFeed_SeverityFromCVSS(t *testing.T) {
	raw, err := os.ReadFile("testdata/cve-feed.json")
	if err != nil {
		t.Fatal(err)
	}
	got, err := vacheck.ParseCVEFeed(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("esperava 3 candidates CVE, veio %d", len(got))
	}
	var crit bool
	for _, c := range got {
		if vacheck.NormalizeSeverity(c.Severity) == "" {
			t.Fatalf("severity invalida: %q", c.Severity)
		}
		if c.Severity == db.SeverityCritical {
			crit = true
		}
		if len(c.Refs) == 0 {
			t.Fatalf("candidate CVE sem Refs: %+v", c)
		}
	}
	if !crit {
		t.Fatal("CVSS 9.8 deveria mapear para critical")
	}
}

func TestParseCVEFeed_MalformedNoPanic(t *testing.T) {
	if _, err := vacheck.ParseCVEFeed([]byte("[{bad")); err == nil {
		t.Fatal("esperava erro em JSON malformado")
	}
}
