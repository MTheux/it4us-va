package vareport

import (
	"strings"
	"testing"

	"github.com/MTheux/it4us-va/db"
)

func TestToFindingPayloadBasic(t *testing.T) {
	f := &db.DBFinding{Name: "TLS 1.0 habilitado", VulnClass: "tls.weak", Severity: "medium", Summary: "O serviço aceita TLS 1.0.", Evidence: "port=443 proto=TLSv1.0"}
	p, err := ToFindingPayload(f)
	if err != nil {
		t.Fatal(err)
	}
	if p.Title != "TLS 1.0 habilitado" || p.Severity != "medium" || p.RetestStatus != "new" {
		t.Errorf("payload=%+v", p)
	}
	if !strings.Contains(p.Description, "Condição observada") || !strings.Contains(p.Description, "read-only") {
		t.Errorf("description sem enquadramento VA: %q", p.Description)
	}
}

func TestToFindingPayloadRejectsExploitationLanguage(t *testing.T) {
	f := &db.DBFinding{Name: "x", VulnClass: "rce", Severity: "high", Summary: "ok", Report: "Em seguida exploramos a falha e obtivemos shell no servidor."}
	if _, err := ToFindingPayload(f); err == nil {
		t.Fatal("esperava erro de enquadramento de pentest")
	}
}

func TestToFindingPayloadNoPII(t *testing.T) {
	f := &db.DBFinding{Name: "Exposição de dados", VulnClass: "sql.exposure", Severity: "high", Summary: "Tabela users exposta", Evidence: "amostra: email=alice@example.com cpf=123.456.789-00"}
	p, err := ToFindingPayload(f)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(p.Description, "alice@example.com") || strings.Contains(p.Description, "123.456.789-00") {
		t.Errorf("PII vazou no payload: %q", p.Description)
	}
}
