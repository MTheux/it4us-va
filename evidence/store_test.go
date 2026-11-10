package evidence

import (
	"context"
	"testing"

	"github.com/MTheux/it4us-va/db"
)

// TestNewSignatureNoTraffic garante que o construtor do store não depende mais
// do proxy MITM (excisão ofensiva, Plano 3): New(pg, dir), sem *traffic.Traffic.
func TestNewSignatureNoTraffic(t *testing.T) {
	s := New(nil, t.TempDir())
	if s == nil || s.Dir == "" {
		t.Fatal("New(pg, dir) deve construir um Store com Dir")
	}
}

// TestPrepareDormant prova o contrato pós-excisão: sem captura MITM não há
// exchange para ler, então uma lista vazia de refs é aceita (finding sem
// bindings), e qualquer ref explícita falha fail-closed — nunca grava evidência
// de uma fonte que não existe mais. A evidência de scanner será ligada no
// pipeline de VA (Plano 4).
func TestPrepareDormant(t *testing.T) {
	s := New(nil, t.TempDir())

	out, err := s.prepare(context.Background(), nil)
	if err != nil {
		t.Fatalf("refs vazias devem ser aceitas, got err=%v", err)
	}
	if len(out) != 0 {
		t.Fatalf("refs vazias devem produzir zero evidências, got %d", len(out))
	}

	if _, err := s.prepare(context.Background(), []db.TrafficRef{{TrafficID: "x"}}); err == nil {
		t.Fatal("ref explícita deve falhar fail-closed após a remoção da captura MITM")
	}
}
