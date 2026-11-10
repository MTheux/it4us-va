package server

import (
	"context"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/MTheux/it4us-va/db"
)

// trafficEvidenceServer monta um Server de teste com um finding gravado (sem
// bindings de evidência). O nome é histórico: a captura MITM foi removida na
// excisão ofensiva (Plano 3), então o fixture já não abre um proxy de traffic —
// grava o finding pelo caminho read-only de evidência (refs nil).
func trafficEvidenceServer(t *testing.T) (*Server, *db.RecordedFinding, func(string, string, string) *httptest.ResponseRecorder) {
	t.Helper()
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close() })
	task, err := m.CreateTask("evidence API", "local evidence", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	tid, _ := strconv.ParseInt(task.ID, 10, 64)
	t.Cleanup(func() { m.pg.Exec(`DELETE FROM task_archives WHERE task_id=$1`, tid); m.pg.DeleteTask(tid) })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	s.archiveWG.Wait()
	// The archive test replaces the cancelled service context. Wait for the
	// side-question snapshot writer too before reusing this fixture.
	<-s.side.done
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	input := db.RecordFindingInput{TaskID: tid, ExplorationID: task.ExpID, Worker: "test", VulnClass: "TEST", Summary: "evidence", Name: "Evidence API", Severity: "low"}
	f, err := s.evidenceStore().Record(context.Background(), input, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s, f, request
}
