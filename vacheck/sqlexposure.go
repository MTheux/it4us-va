package vacheck

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/MTheux/it4us-va/db"
)

func init() {
	Register(Check{
		ID:           "sql.exposure",
		Title:        "Exposição da camada de dados (SQL)",
		Tool:         "mssql-ro-probe",
		ReadOnlyArgs: []string{"--auth-mode", "--list-linked", "--schema-only"},
		ForeSea:      "camada de dados (sa, linked servers, metadados)",
		Parse:        ParseSQLExposure,
	})
}

// sqlExposure is the schema of a read-only SQL probe. Note deliberately: there
// is NO sampleRows / data-row field here. Any such field in the raw JSON is
// never deserialized, which is how the no-PII guarantee is enforced structurally
// — the parser cannot leak what it never reads.
type sqlExposure struct {
	Host          string   `json:"host"`
	Instance      string   `json:"instance"`
	AuthMode      string   `json:"authMode"`
	SAEnabled     bool     `json:"saEnabled"`
	LinkedServers []string `json:"linkedServers"`
	Databases     []struct {
		Name   string `json:"name"`
		Tables []struct {
			Schema   string   `json:"schema"`
			Table    string   `json:"table"`
			RowCount int      `json:"rowCount"`
			Columns  []string `json:"columns"`
			// sampleRows intentionally omitted — no-PII.
		} `json:"tables"`
	} `json:"databases"`
}

// sensitiveColumns are column-name hints that make a table worth flagging as
// sensitive data exposure. Only the column NAME (metadata) is ever recorded.
var sensitiveColumns = []string{"cpf", "cnpj", "senha", "password", "cartao", "card", "rg", "email", "salario", "token"}

// ParseSQLExposure reads a read-only SQL probe and flags sa/mixed-mode auth,
// linked servers, and sensitive-data tables — using counts, schema, table and
// column NAMES only. It never emits data-row values.
func ParseSQLExposure(raw []byte) ([]Candidate, error) {
	var sx sqlExposure
	if err := json.Unmarshal(raw, &sx); err != nil {
		return nil, fmt.Errorf("vacheck: JSON do probe SQL invalido: %w", err)
	}
	asset := Asset{Host: sx.Host, IP: sx.Host, Service: "mssql"}
	var out []Candidate

	if sx.SAEnabled || strings.EqualFold(sx.AuthMode, "mixed") {
		out = append(out, Candidate{
			Check: "sql.exposure", VulnClass: "sql-sa-exposto", Severity: db.SeverityHigh, Asset: asset,
			Title:    fmt.Sprintf("SQL Server com autenticação mista / conta sa habilitada (%s)", sx.Host),
			Summary:  fmt.Sprintf("A instância %s em %s usa modo de autenticação mista com a conta 'sa' habilitada. A conta sa é alvo de força bruta e, se comprometida, concede controle total; recomenda-se autenticação integrada e desabilitar/renomear sa.", sx.Instance, sx.Host),
			Evidence: fmt.Sprintf("authMode=%s saEnabled=%v instance=%s", sx.AuthMode, sx.SAEnabled, sx.Instance),
			Tags:     []string{"foresea:dados"},
		})
	}

	if len(sx.LinkedServers) > 0 {
		out = append(out, Candidate{
			Check: "sql.exposure", VulnClass: "sql-linked-servers", Severity: db.SeverityMedium, Asset: asset,
			Title:    fmt.Sprintf("Linked servers configurados (%d) em %s", len(sx.LinkedServers), sx.Host),
			Summary:  fmt.Sprintf("A instância %s possui %d linked server(s) configurado(s). Linked servers podem permitir movimento lateral entre instâncias via consultas distribuídas; revisar necessidade e contexto de credencial.", sx.Host, len(sx.LinkedServers)),
			Evidence: fmt.Sprintf("linkedServers=%v", sx.LinkedServers),
			Tags:     []string{"foresea:dados"},
		})
	}

	for _, d := range sx.Databases {
		for _, tb := range d.Tables {
			if hit := matchSensitive(tb.Columns); hit != "" {
				out = append(out, Candidate{
					Check: "sql.exposure", VulnClass: "sql-dados-sensiveis", Severity: db.SeverityMedium, Asset: asset,
					Title:    fmt.Sprintf("Tabela com dados sensíveis: %s.%s.%s", d.Name, tb.Schema, tb.Table),
					Summary:  fmt.Sprintf("A tabela %s.%s.%s (%d linhas) possui coluna(s) sensível(is) (ex.: %s). Registrado apenas metadado (contagem e nomes de coluna); nenhum dado pessoal foi extraído. Avaliar criptografia/mascaramento e controle de acesso.", d.Name, tb.Schema, tb.Table, tb.RowCount, hit),
					Evidence: fmt.Sprintf("%s.%s.%s rowCount=%d columns=%v", d.Name, tb.Schema, tb.Table, tb.RowCount, tb.Columns),
					Tags:     []string{"foresea:dados"},
				})
			}
		}
	}
	return out, nil
}

func matchSensitive(cols []string) string {
	for _, c := range cols {
		lc := strings.ToLower(c)
		for _, s := range sensitiveColumns {
			if lc == s {
				return c
			}
		}
	}
	return ""
}
