package vacheck

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/MTheux/it4us-va/db"
)

func init() {
	Register(Check{
		ID:           "shares.perms",
		Title:        "Permissões de compartilhamentos SMB/NTFS",
		Tool:         "smbmap",
		ReadOnlyArgs: []string{"-H", "<host>", "--no-banner"},
		ForeSea:      "compartilhamentos/NTFS",
		Parse:        ParseShares,
	})
}

// smbShares is the schema of a read-only share listing. File CONTENT is never
// modeled here (only file name/size), so sensitive file contents in the raw
// output cannot reach a Candidate — the no-PII guarantee is structural.
type smbShares struct {
	Host   string `json:"host"`
	Shares []struct {
		Name       string `json:"name"`
		Permission string `json:"permission"`
		Access     string `json:"access"`
		Files      []struct {
			Name string `json:"name"`
			Size int64  `json:"size"`
			// content_preview intentionally omitted — no-PII.
		} `json:"files"`
	} `json:"shares"`
}

// broadAccess reports whether an access principal means "anyone".
func broadAccess(access string) bool {
	a := strings.ToLower(access)
	return strings.Contains(a, "anonymous") || strings.Contains(a, "everyone") || strings.Contains(a, "guest") || strings.Contains(a, "null session")
}

// ParseShares flags shares reachable by anonymous/everyone, grading writable
// higher than readable, and sensitive AD shares (SYSVOL/NETLOGON) writable as
// high. It records share name, permission and file NAMES only — never content.
func ParseShares(raw []byte) ([]Candidate, error) {
	var s smbShares
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("vacheck: JSON de shares invalido: %w", err)
	}
	asset := Asset{Host: s.Host, IP: s.Host, Service: "smb"}
	var out []Candidate
	for _, sh := range s.Shares {
		perm := strings.ToUpper(sh.Permission)
		if strings.Contains(perm, "NO ACCESS") || perm == "" {
			continue
		}
		writable := strings.Contains(perm, "WRITE")
		readable := strings.Contains(perm, "READ")
		sysvol := strings.EqualFold(sh.Name, "SYSVOL") || strings.EqualFold(sh.Name, "NETLOGON")

		var sev, cls, title string
		switch {
		case writable && (broadAccess(sh.Access) || sysvol):
			sev, cls = db.SeverityHigh, "share-gravavel-amplo"
			title = fmt.Sprintf("Compartilhamento gravável por acesso amplo: %s", sh.Name)
		case readable && broadAccess(sh.Access):
			sev, cls = db.SeverityMedium, "share-legivel-amplo"
			title = fmt.Sprintf("Compartilhamento legível por acesso amplo: %s", sh.Name)
		default:
			continue
		}
		out = append(out, Candidate{
			Check: "shares.perms", VulnClass: cls, Severity: sev, Asset: asset,
			Title:    title,
			Summary:  fmt.Sprintf("O compartilhamento '%s' em %s está acessível (%s) para o principal '%s'. Acesso amplo a shares permite leitura/escrita indevida; restringir ACLs ao mínimo necessário.", sh.Name, s.Host, sh.Permission, sh.Access),
			Evidence: fmt.Sprintf("share=%s permission=%q access=%q arquivos=%d", sh.Name, sh.Permission, sh.Access, len(sh.Files)),
			Tags:     []string{"foresea:shares"},
		})
	}
	return out, nil
}
