// Package vareport builds and pushes a VA (vulnerability-assessment) report to
// SysReptor from the findings of a finalized IT4US VA run. VA, not pentest:
// findings stop at the observed condition and its read-only evidence.
package vareport

import "strings"

// NormalizeSeverity maps any finding severity to a SysReptor severity enum
// value. SysReptor accepts: extreme, critical, high, medium, low, info.
// Unknown or empty input returns "info" — never empty, never out-of-enum.
func NormalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "extreme":
		return "extreme"
	case "critical", "crit":
		return "critical"
	case "high":
		return "high"
	case "medium", "med", "moderate":
		return "medium"
	case "low":
		return "low"
	case "info", "informational", "none":
		return "info"
	default:
		return "info"
	}
}
