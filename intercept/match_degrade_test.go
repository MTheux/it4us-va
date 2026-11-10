package intercept

import (
	"context"
	"os"
	"testing"

	"github.com/MTheux/it4us-va/db"
)

// TestMain inicializa um banco próprio quando IT4US_PG_DSN está setado; sem DSN,
// os testes que exigem DB fazem skip. Espelha o padrão do pacote evidence (#80).
func TestMain(m *testing.M) {
	db.SuffixTestDatabase("intercept")
	if os.Getenv("IT4US_PG_DSN") == "" {
		os.Exit(m.Run())
	}
	pg, err := db.Open(os.Getenv("IT4US_PG_DSN"))
	if err != nil {
		panic(err)
	}
	defer pg.Close()
	conn, err := pg.Conn(context.Background())
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	if _, err = conn.ExecContext(context.Background(), `SELECT pg_advisory_lock(7337741003)`); err != nil {
		panic(err)
	}
	defer conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock(7337741003)`)
	os.Exit(m.Run())
}

// TestAskRuleDegradesToDeny prova o contrato da excisão ofensiva (Plano 3): uma
// regra legada com ação "ask" (aprovação MITM-interativa, removida) degrada para
// "deny" (fail-closed) no Match — nunca para "allow".
func TestAskRuleDegradesToDeny(t *testing.T) {
	if os.Getenv("IT4US_PG_DSN") == "" {
		t.Skip("sem IT4US_PG_DSN")
	}
	pg, err := db.Open(os.Getenv("IT4US_PG_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pg.Close() })

	if _, err := pg.CreateInterceptRule("legacy-ask", "tool_name", "string", "Bash", "ask", "", 100, true, false, 0, "deny"); err != nil {
		t.Fatal(err)
	}
	ic := New(pg)
	dec, matched := ic.Match("Bash", []byte(`{"cmd":"id"}`))
	if !matched {
		t.Fatal("a regra deveria casar com a tool Bash")
	}
	if dec.Action != "deny" {
		t.Fatalf("ação legada ask deveria degradar para deny (fail-closed), got %q", dec.Action)
	}
}
