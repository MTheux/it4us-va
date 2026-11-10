package vacheck_test

import (
	"strings"
	"testing"

	"github.com/MTheux/it4us-va/db"
	"github.com/MTheux/it4us-va/vacheck"
)

func TestRegisterAndGet(t *testing.T) {
	vacheck.Register(vacheck.Check{
		ID:    "zzz.test",
		Title: "t",
		Tool:  "nmap",
		Parse: func([]byte) ([]vacheck.Candidate, error) { return nil, nil },
	})
	c, ok := vacheck.Get("zzz.test")
	if !ok || c.ID != "zzz.test" {
		t.Fatal("check nao registrado")
	}
}

func TestNormalizeSeverity(t *testing.T) {
	cases := map[string]string{
		"HIGH":  db.SeverityHigh,
		" low ": db.SeverityLow,
		"info":  db.SeverityLow,
		"bogus": "",
	}
	for in, want := range cases {
		if got := vacheck.NormalizeSeverity(in); got != want {
			t.Fatalf("NormalizeSeverity(%q)=%q, quer %q", in, got, want)
		}
	}
}

func TestNoIntrusiveArgs(t *testing.T) {
	for _, c := range vacheck.All() {
		joined := strings.ToLower(strings.Join(c.ReadOnlyArgs, " "))
		for _, bad := range vacheck.IntrusiveTokens() {
			if strings.Contains(joined, bad) {
				t.Fatalf("check %q carrega token intrusivo %q em ReadOnlyArgs", c.ID, bad)
			}
		}
	}
}
