package vacheck

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/MTheux/it4us-va/db"
)

func init() {
	Register(Check{
		ID:           "ad.hygiene",
		Title:        "Higiene de Active Directory",
		Tool:         "ldapsearch",
		ReadOnlyArgs: []string{"-x", "-LLL", "-b", "<base>"},
		ForeSea:      "higiene AD (krbtgt, sIDHistory, admin sprawl)",
		Parse:        ParseADHygiene,
	})
}

// Hygiene thresholds (named so the policy is explicit and tunable).
const (
	krbtgtStaleHigh   = 365 * 24 * time.Hour // senha do krbtgt muito antiga
	krbtgtStaleMedium = 180 * 24 * time.Hour
	adminSprawlLimit  = 10 // membros de grupo privilegiado acima disto = sprawl
)

type adHygiene struct {
	Domain string `json:"domain"`
	Krbtgt struct {
		PwdLastSet time.Time `json:"pwdLastSet"`
	} `json:"krbtgt"`
	SidHistory []struct {
		SAMAccountName string   `json:"sAMAccountName"`
		SidHistory     []string `json:"sidHistory"`
	} `json:"sidHistory"`
	PrivilegedGroups []struct {
		Group       string `json:"group"`
		MemberCount int    `json:"memberCount"`
	} `json:"privilegedGroups"`
}

// ParseADHygiene reads a read-only LDAP hygiene snapshot and flags stale krbtgt
// password, populated sIDHistory, and privileged-group sprawl. It records counts
// and group/account names only — never hashes or secrets.
func ParseADHygiene(raw []byte) ([]Candidate, error) {
	var ad adHygiene
	if err := json.Unmarshal(raw, &ad); err != nil {
		return nil, fmt.Errorf("vacheck: JSON de higiene AD invalido: %w", err)
	}
	asset := Asset{Host: ad.Domain, Service: "activedirectory"}
	var out []Candidate

	// krbtgt password age
	if !ad.Krbtgt.PwdLastSet.IsZero() {
		age := time.Since(ad.Krbtgt.PwdLastSet)
		sev := ""
		switch {
		case age >= krbtgtStaleHigh:
			sev = db.SeverityHigh
		case age >= krbtgtStaleMedium:
			sev = db.SeverityMedium
		}
		if sev != "" {
			days := int(age.Hours() / 24)
			out = append(out, Candidate{
				Check: "ad.hygiene", VulnClass: "krbtgt-senha-antiga", Severity: sev, Asset: asset,
				Title:    fmt.Sprintf("Senha do krbtgt não rotacionada há %d dias", days),
				Summary:  fmt.Sprintf("A conta krbtgt de %s teve a senha definida pela última vez em %s (%d dias). Krbtgt antigo facilita Golden Tickets de longa duração; recomenda-se rotação periódica (duas vezes).", ad.Domain, ad.Krbtgt.PwdLastSet.Format("2006-01-02"), days),
				Evidence: fmt.Sprintf("krbtgt.pwdLastSet=%s; idade=%dd", ad.Krbtgt.PwdLastSet.Format(time.RFC3339), days),
				Tags:     []string{"foresea:ad-hygiene"},
			})
		}
	}

	// sIDHistory presence (aggregate)
	if n := len(ad.SidHistory); n > 0 {
		names := make([]string, 0, n)
		for _, o := range ad.SidHistory {
			names = append(names, o.SAMAccountName)
		}
		out = append(out, Candidate{
			Check: "ad.hygiene", VulnClass: "sidhistory-populado", Severity: db.SeverityMedium, Asset: asset,
			Title:    fmt.Sprintf("%d objeto(s) com sIDHistory populado", n),
			Summary:  fmt.Sprintf("Em %s, %d objeto(s) possuem sIDHistory populado. sIDHistory residual pode conceder privilégios herdados não óbvios e deve ser auditado/limpo após migrações.", ad.Domain, n),
			Evidence: fmt.Sprintf("contas com sIDHistory: %v", names),
			Tags:     []string{"foresea:ad-hygiene"},
		})
	}

	// privileged-group sprawl
	for _, g := range ad.PrivilegedGroups {
		if g.MemberCount > adminSprawlLimit {
			out = append(out, Candidate{
				Check: "ad.hygiene", VulnClass: "admin-sprawl", Severity: db.SeverityMedium, Asset: asset,
				Title:    fmt.Sprintf("Grupo privilegiado numeroso: %s (%d membros)", g.Group, g.MemberCount),
				Summary:  fmt.Sprintf("O grupo '%s' em %s tem %d membros (acima do limiar de %d). Grupos Tier 0 numerosos ampliam a superfície de comprometimento; aplicar least-privilege.", g.Group, ad.Domain, g.MemberCount, adminSprawlLimit),
				Evidence: fmt.Sprintf("%s memberCount=%d", g.Group, g.MemberCount),
				Tags:     []string{"foresea:ad-hygiene"},
			})
		}
	}
	return out, nil
}
