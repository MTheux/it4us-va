package vareport

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/MTheux/it4us-va/db"
)

// exploitationVerbs are markers of pentest exploitation language. A VA report
// stops at the observed condition, so a finding carrying any of these is not
// VA-framed and must be rewritten before it can be reported.
var exploitationVerbs = []string{
	"exploramos", "explorada com sucesso", "exploração bem-sucedida",
	"shell obtida", "reverse shell", "payload executado", "rce confirmad",
	"comando executado no servidor", "acesso obtido via explor",
	"we exploited", "gained shell", "popped a shell", "command executed on",
}

var (
	reEmail = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	reCPF   = regexp.MustCompile(`\b\d{3}\.\d{3}\.\d{3}-\d{2}\b`)
	reCard  = regexp.MustCompile(`\b(?:\d[ \-]?){13,19}\b`)
)

const redacted = "[REDACTED:PII]"

// sanitizePII redacts obvious personal data that may have slipped into a
// finding's read-only evidence — defense in depth over vacheck's structural
// no-PII guarantee. Scanner metadata (ports, counts) is untouched.
func sanitizePII(s string) string {
	s = reEmail.ReplaceAllString(s, redacted)
	s = reCPF.ReplaceAllString(s, redacted)
	s = reCard.ReplaceAllString(s, redacted)
	return s
}

// assertVAFraming returns an error when VA-forbidden exploitation language
// appears in the payload text.
func assertVAFraming(p FindingPayload) error {
	hay := strings.ToLower(p.Description + "\n" + p.Impact + "\n" + p.Summary)
	for _, v := range exploitationVerbs {
		if strings.Contains(hay, v) {
			return fmt.Errorf("enquadramento de pentest detectado (%q): finding precisa ser reescrito em termos de VA (condição observada, sem exploração)", v)
		}
	}
	return nil
}

// ToFindingPayload maps a finalized VA finding to a VA-framed SysReptor payload.
// It sanitizes PII from the evidence and rejects findings written with
// exploitation language.
func ToFindingPayload(f *db.DBFinding) (FindingPayload, error) {
	title := strings.TrimSpace(f.Name)
	if title == "" {
		title = f.VulnClass
	}
	evidence := sanitizePII(strings.TrimSpace(f.Evidence))
	detail := strings.TrimSpace(f.Report)
	if detail == "" {
		detail = strings.TrimSpace(f.Summary)
	}
	detail = sanitizePII(detail)

	var desc strings.Builder
	desc.WriteString("## Condição observada\n\n")
	desc.WriteString(detail)
	if evidence != "" {
		desc.WriteString("\n\n## Evidência (captura read-only)\n\n```\n")
		desc.WriteString(evidence)
		desc.WriteString("\n```\n")
	}

	sev := NormalizeSeverity(f.Severity)
	impact := fmt.Sprintf("Exposição identificada por avaliação não-intrusiva. Criticidade: %s. Classe: %s.", sev, f.VulnClass)

	p := FindingPayload{
		Title:        title,
		Severity:     sev,
		Summary:      sanitizePII(strings.TrimSpace(f.Summary)),
		Impact:       impact,
		Description:  desc.String(),
		RetestStatus: "new",
	}
	if err := assertVAFraming(p); err != nil {
		return FindingPayload{}, err
	}
	return p, nil
}
