package vareport

import "testing"

func TestNormalizeSeverity(t *testing.T) {
	cases := map[string]string{
		"critical":  "critical",
		"CRITICAL":  "critical",
		"high":      "high",
		"medium":    "medium",
		"low":       "low",
		"":          "info",
		"EXPLOITED": "info",
		"extreme":   "extreme",
	}
	for in, want := range cases {
		if got := NormalizeSeverity(in); got != want {
			t.Errorf("NormalizeSeverity(%q)=%q want %q", in, got, want)
		}
	}
}
