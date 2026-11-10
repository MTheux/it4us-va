package vacheck

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/MTheux/it4us-va/db"
)

func init() {
	Register(Check{
		ID:           "tls.weak",
		Title:        "Configuração TLS fraca (protocolos/cifras)",
		Tool:         "testssl.sh",
		ReadOnlyArgs: []string{"--jsonfile-pretty", "-", "--quiet"},
		ForeSea:      "TLS/cifras",
		Parse:        ParseTLS,
	})
}

type testsslEntry struct {
	ID       string `json:"id"`
	IP       string `json:"ip"`
	Port     string `json:"port"`
	Severity string `json:"severity"`
	Finding  string `json:"finding"`
}

// tlsSeverity maps a testssl severity label onto a db severity, or "" when the
// entry is not a weakness (OK/INFO/DEBUG) and must produce no candidate.
func tlsSeverity(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return db.SeverityCritical
	case "HIGH":
		return db.SeverityHigh
	case "MEDIUM":
		return db.SeverityMedium
	case "LOW", "WARN":
		return db.SeverityLow
	default: // OK, INFO, DEBUG, ""
		return ""
	}
}

// ParseTLS turns testssl.sh --jsonfile-pretty output into Candidates, one per
// weakness entry. OK/INFO entries are skipped, so a strong host yields nothing.
func ParseTLS(raw []byte) ([]Candidate, error) {
	var entries []testsslEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("vacheck: JSON do testssl invalido: %w", err)
	}
	var out []Candidate
	for _, e := range entries {
		sev := tlsSeverity(e.Severity)
		if sev == "" {
			continue
		}
		ip := e.IP
		if i := strings.IndexByte(ip, '/'); i >= 0 {
			ip = ip[:i]
		}
		out = append(out, Candidate{
			Check:     "tls.weak",
			Title:     fmt.Sprintf("Fraqueza TLS: %s", e.ID),
			VulnClass: "tls-fraco",
			Severity:  sev,
			Asset:     Asset{IP: ip, Service: "tls"},
			Summary:   fmt.Sprintf("A verificação TLS '%s' retornou: %s. Protocolos obsoletos e cifras fracas permitem interceptação/rebaixamento e devem ser desabilitados.", e.ID, strings.TrimSpace(e.Finding)),
			Evidence:  fmt.Sprintf("%s: %s", e.ID, strings.TrimSpace(e.Finding)),
			Tags:      []string{"foresea:tls"},
		})
	}
	return out, nil
}
