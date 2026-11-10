package vacheck

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/MTheux/it4us-va/db"
)

func init() {
	Register(Check{
		ID:           "cve.version",
		Title:        "Correlação versão de serviço → CVE",
		Tool:         "mcp:cve-feed",
		ReadOnlyArgs: nil, // coleta ao vivo via MCP é da camada de orquestração (fora deste pacote)
		ForeSea:      "versão/serviço → CVE",
		Parse:        ParseCVEFeed,
	})
}

// CVEQueries builds deduplicated CVE-lookup query strings from nmap service
// candidates (product+version banners). Pure transform — no network.
func CVEQueries(cands []Candidate) []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range cands {
		if c.Check != "nmap.service" {
			continue
		}
		q := bannerOf(c)
		if q == "" || seen[q] {
			continue
		}
		seen[q] = true
		out = append(out, q)
	}
	sort.Strings(out)
	return out
}

// bannerOf extracts the product+version banner from a nmap candidate's Evidence
// (the text after "-> "), falling back to the service name.
func bannerOf(c Candidate) string {
	if i := strings.Index(c.Evidence, "-> "); i >= 0 {
		return strings.TrimSpace(c.Evidence[i+3:])
	}
	if s := strings.TrimSpace(c.Evidence); s != "" {
		return s
	}
	return strings.TrimSpace(c.Asset.Service)
}

type cveEntry struct {
	ID       string  `json:"id"`
	CVSS     float64 `json:"cvss"`
	Title    string  `json:"title"`
	Affected string  `json:"affected"`
}

// cvssSeverity maps a CVSS base score onto a db severity.
func cvssSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return db.SeverityCritical
	case score >= 7.0:
		return db.SeverityHigh
	case score >= 4.0:
		return db.SeverityMedium
	default:
		return db.SeverityLow
	}
}

// ParseCVEFeed turns a CVE feed response (vulners/OTX-style list) into
// Candidates, severity derived from the CVSS base score, Refs set to the CVE id.
func ParseCVEFeed(raw []byte) ([]Candidate, error) {
	var entries []cveEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("vacheck: JSON do feed de CVE invalido: %w", err)
	}
	var out []Candidate
	for _, e := range entries {
		out = append(out, Candidate{
			Check: "cve.version", VulnClass: "cve-conhecida", Severity: cvssSeverity(e.CVSS),
			Asset:    Asset{Service: e.Affected},
			Title:    fmt.Sprintf("%s — %s (CVSS %.1f)", e.ID, e.Title, e.CVSS),
			Summary:  fmt.Sprintf("O serviço '%s' corresponde à %s (%s, CVSS %.1f). Achado por correlação de versão; validar aplicabilidade do patch e exposição.", e.Affected, e.ID, e.Title, e.CVSS),
			Evidence: fmt.Sprintf("%s cvss=%.1f affected=%s", e.ID, e.CVSS, e.Affected),
			Tags:     []string{"foresea:cve"},
			Refs:     []string{e.ID},
		})
	}
	return out, nil
}
