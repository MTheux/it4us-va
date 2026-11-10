package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoTrafficRoutes é a guarda anti-regressão da excisão do engine ofensivo
// (Plano 3, Task 1): nenhuma rota HTTP de proxy MITM (traffic) pode voltar a ser
// registrada no pacote server. Varre o fonte Go do pacote em busca de registros
// de rota `/api/traffic` e `.../findings/{id}/traffic`.
func TestNoTrafficRoutes(t *testing.T) {
	// A guarda mira a regressão do PROXY MITM (rotas /api/traffic/*). As rotas de
	// evidência de finding (/api/exploration/findings/{id}/traffic) são o esqueleto
	// de evidência dormente preservado para o pipeline de VA (Plano 4), não captura
	// MITM, e por isso não entram aqui.
	forbidden := []string{
		`"GET /api/traffic`,
		`"DELETE /api/traffic`,
		`"POST /api/traffic`,
		`/api/traffic/`,
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") {
			continue
		}
		if strings.HasSuffix(name, "_test.go") {
			continue // não auditar os próprios testes
		}
		b, err := os.ReadFile(filepath.Join(".", name))
		if err != nil {
			t.Fatalf("ReadFile %s: %v", name, err)
		}
		src := string(b)
		for _, pat := range forbidden {
			if strings.Contains(src, pat) {
				t.Errorf("rota de traffic (MITM) ainda registrada em %s: contém %q", name, pat)
			}
		}
	}
}
