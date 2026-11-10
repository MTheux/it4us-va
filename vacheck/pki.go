package vacheck

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/MTheux/it4us-va/db"
)

func init() {
	Register(Check{
		ID:           "pki.cert",
		Title:        "Higiene de certificado X.509",
		Tool:         "openssl",
		ReadOnlyArgs: []string{"x509", "-noout", "-text"},
		ForeSea:      "PKI/ADCS validade/expiração, chaves/assinaturas",
		Parse:        ParsePKI,
	})
	Register(Check{
		ID:           "adcs.template",
		Title:        "Template ADCS potencialmente vulnerável (enumeração)",
		Tool:         "certipy",
		ReadOnlyArgs: []string{"find", "-vulnerable", "-json"},
		ForeSea:      "PKI/ADCS templates (ESC)",
		Parse:        ParseADCS,
	})
}

// expiryWindow is the horizon under which a not-yet-expired cert is flagged.
const expiryWindow = 30 * 24 * time.Hour

// ParsePKI decodes a PEM X.509 certificate and flags weak key size, weak
// signature algorithm, and expiry (expired or within expiryWindow).
func ParsePKI(raw []byte) ([]Candidate, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("vacheck: entrada nao contem bloco PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("vacheck: certificado X.509 invalido: %w", err)
	}
	subject := cert.Subject.CommonName
	asset := Asset{Host: subject, Service: "pki"}
	var out []Candidate

	// weak key
	if k, ok := cert.PublicKey.(*rsa.PublicKey); ok && k.N.BitLen() < 2048 {
		out = append(out, Candidate{
			Check: "pki.cert", VulnClass: "chave-fraca", Severity: db.SeverityHigh, Asset: asset,
			Title:    fmt.Sprintf("Chave RSA fraca (%d bits) em %s", k.N.BitLen(), subject),
			Summary:  fmt.Sprintf("O certificado de %s usa chave RSA de %d bits (< 2048). Chaves abaixo de 2048 bits são consideradas quebráveis e devem ser reemitidas.", subject, k.N.BitLen()),
			Evidence: fmt.Sprintf("RSA %d bits; subject=%s", k.N.BitLen(), subject),
			Tags:     []string{"foresea:pki"},
		})
	}
	// weak signature
	if sa := cert.SignatureAlgorithm.String(); isWeakSig(sa) {
		out = append(out, Candidate{
			Check: "pki.cert", VulnClass: "assinatura-fraca", Severity: db.SeverityMedium, Asset: asset,
			Title:    fmt.Sprintf("Assinatura de certificado fraca (%s) em %s", sa, subject),
			Summary:  fmt.Sprintf("O certificado de %s foi assinado com %s. Algoritmos SHA1/MD5 têm colisões práticas e devem ser substituídos por SHA-256+.", subject, sa),
			Evidence: fmt.Sprintf("SignatureAlgorithm=%s; subject=%s", sa, subject),
			Tags:     []string{"foresea:pki"},
		})
	}
	// expiry
	now := time.Now()
	if now.After(cert.NotAfter) {
		out = append(out, Candidate{
			Check: "pki.cert", VulnClass: "certificado-expirado", Severity: db.SeverityMedium, Asset: asset,
			Title:    fmt.Sprintf("Certificado expirado em %s", subject),
			Summary:  fmt.Sprintf("O certificado de %s expirou em %s.", subject, cert.NotAfter.Format("2006-01-02")),
			Evidence: fmt.Sprintf("notAfter=%s; subject=%s", cert.NotAfter.Format(time.RFC3339), subject),
			Tags:     []string{"foresea:pki"},
		})
	} else if cert.NotAfter.Sub(now) < expiryWindow {
		days := int(cert.NotAfter.Sub(now).Hours() / 24)
		out = append(out, Candidate{
			Check: "pki.cert", VulnClass: "certificado-expirando", Severity: db.SeverityLow, Asset: asset,
			Title:    fmt.Sprintf("Certificado expirando em %d dias em %s", days, subject),
			Summary:  fmt.Sprintf("O certificado de %s expira em %s (%d dias). Renovar antes do vencimento para evitar indisponibilidade.", subject, cert.NotAfter.Format("2006-01-02"), days),
			Evidence: fmt.Sprintf("notAfter=%s; subject=%s", cert.NotAfter.Format(time.RFC3339), subject),
			Tags:     []string{"foresea:pki"},
		})
	}
	return out, nil
}

func isWeakSig(sa string) bool {
	s := strings.ToLower(sa)
	return strings.Contains(s, "sha1") || strings.Contains(s, "md5") || strings.Contains(s, "md2")
}

// certipy find -json subset.
type certipyFind struct {
	Templates map[string]certipyTemplate `json:"Certificate Templates"`
}

type certipyTemplate struct {
	Name            string            `json:"Template Name"`
	Vulnerabilities map[string]string `json:"[!] Vulnerabilities"`
}

// ParseADCS reads certipy find -json output and flags each template that certipy
// marked vulnerable (ESC*). These are ENUMERATION findings: they report the
// exposure, they do not exploit it — validation is a human/next-phase step.
func ParseADCS(raw []byte) ([]Candidate, error) {
	var f certipyFind
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("vacheck: JSON do certipy invalido: %w", err)
	}
	var out []Candidate
	for _, tpl := range f.Templates {
		if len(tpl.Vulnerabilities) == 0 {
			continue
		}
		escs := make([]string, 0, len(tpl.Vulnerabilities))
		for esc := range tpl.Vulnerabilities {
			escs = append(escs, esc)
		}
		out = append(out, Candidate{
			Check: "adcs.template", VulnClass: "adcs-template-vulneravel", Severity: db.SeverityHigh,
			Asset:    Asset{Host: tpl.Name, Service: "adcs"},
			Title:    fmt.Sprintf("Template ADCS potencialmente vulnerável: %s (%s) — requer validação", tpl.Name, strings.Join(escs, ",")),
			Summary:  fmt.Sprintf("A enumeração do ADCS sinalizou o template '%s' como potencialmente vulnerável (%s). Achado de enumeração, não explorado: validar manualmente e restringir permissões de enrollment/EKU.", tpl.Name, strings.Join(escs, ", ")),
			Evidence: fmt.Sprintf("template=%s vulnerabilities=%s", tpl.Name, strings.Join(escs, ",")),
			Tags:     []string{"foresea:adcs"},
		})
	}
	return out, nil
}
