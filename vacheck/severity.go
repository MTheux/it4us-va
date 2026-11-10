package vacheck

import (
	"strings"

	"github.com/MTheux/it4us-va/db"
)

// NormalizeSeverity lowercases/trims s, maps common synonyms, and returns a
// valid db severity constant, or "" if s is not a recognizable severity.
func NormalizeSeverity(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "info", "informational", "informative", "none":
		s = db.SeverityLow
	}
	if db.ValidSeverity(s) {
		return s
	}
	return ""
}

// intrusiveTokens is the anti-regression denylist: no registered Check may carry
// any of these tokens in ReadOnlyArgs. The bias is conservative — prefer barring
// a borderline arg to letting a state-changing one through. Discovery scans
// (-sS, -sV, -O) are acceptable and deliberately absent.
var intrusiveTokens = []string{
	"brute",
	"exploit",
	"dos",
	"--open-shell",
	"xp_cmdshell",
	"--put",
	"--rm",
	"dcsync",
	"secretsdump",
	"psexec",
	"smbexec",
	"--password-spray",
}

// IntrusiveTokens returns the non-intrusive denylist used by the guard test.
func IntrusiveTokens() []string {
	out := make([]string, len(intrusiveTokens))
	copy(out, intrusiveTokens)
	return out
}
