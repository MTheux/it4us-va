package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestVASOCLocalFlow exercises the SOC path against loopback only. It creates
// an isolated task, reviews scope, runs a single-port discovery, reads the
// receipt, and removes the task. No external host is scanned.
func TestVASOCLocalFlow(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback listener unavailable: %v", err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	defer m.Close()
	// Remove a receipt left by an interrupted earlier invocation of this same
	// isolated test, then keep the normal cleanup tied to the newly created ID.
	rows, err := m.pg.Query(`SELECT id FROM tasks WHERE name='SOC local flow validation'`)
	if err != nil {
		t.Fatal(err)
	}
	var stale []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		stale = append(stale, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		t.Fatal(err)
	}
	rows.Close()
	for _, id := range stale {
		if _, err := m.pg.DeleteTaskCascade(id, true, true); err != nil {
			t.Fatal(err)
		}
	}
	s := &Server{m: m, engine: NewEngine(m), ctx: context.Background(), vaActive: map[string]*vaActiveRun{}}
	call := func(handler http.HandlerFunc, path string, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		rec := httptest.NewRecorder()
		handler(rec, req)
		return rec
	}
	created := call(s.createTask, "/api/tasks", `{"name":"SOC local flow validation","va_only":true,"scope":[{"kind":"ip","value":"127.0.0.1"}]}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("create task: %d %s", created.Code, created.Body.String())
	}
	var task struct {
		ID     string `json:"id"`
		VAOnly bool   `json:"va_only"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &task); err != nil || !task.VAOnly {
		t.Fatalf("task response: %+v, %v", task, err)
	}
	taskID, err := strconv.ParseInt(task.ID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = m.pg.DeleteTaskCascade(taskID, true, true) }()
	blocks, allows, err := m.Assets().TaskVAAllowRules(taskID)
	if err != nil || len(allows) != 1 || allows[0].Pattern != "127.0.0.1" {
		t.Fatalf("task allow scope: blocks=%v allows=%v err=%v", len(blocks), allows, err)
	}
	if scopes, err := m.Assets().ListTaskScope(taskID); err != nil || len(scopes) != 1 || scopes[0].Source != "manual" {
		t.Fatalf("manual task scope: %+v err=%v", scopes, err)
	}
	base := fmt.Sprintf(`{"name":"SOC local flow validation","task_id":%d,"approved_by":"SOC local test","expires_at":%q,"targets":["127.0.0.1"],"depth":"standard","port_profile":"custom","ports":[%d]}`, taskID, time.Now().Add(10*time.Minute).UTC().Format(time.RFC3339), port)
	plan := call(s.vaPlan, "/api/va/plan", base)
	if plan.Code != http.StatusOK {
		t.Fatalf("review plan: %d %s", plan.Code, plan.Body.String())
	}
	outside := strings.Replace(base, `"targets":["127.0.0.1"]`, `"targets":["192.0.2.1"]`, 1)
	if denied := call(s.vaPlan, "/api/va/plan", outside); denied.Code != http.StatusForbidden {
		t.Fatalf("outside scope: %d %s", denied.Code, denied.Body.String())
	}
	started := call(s.vaStartRun, "/api/va/runs", base)
	if started.Code != http.StatusAccepted {
		t.Fatalf("start local discovery: %d %s", started.Code, started.Body.String())
	}
	var run vaRunRecord
	if err := json.Unmarshal(started.Body.Bytes(), &run); err != nil || run.ID == "" {
		t.Fatalf("start receipt: %+v err=%v", run, err)
	}
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		got, err := s.vaReadRecord(run.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.Status != "running" {
			if got.Status != "completed" || got.CompletedHosts != 1 || got.Result == nil || len(got.Result.Hosts) != 1 || len(got.Result.Hosts[0].Services) != 1 {
				t.Fatalf("final receipt: status=%s completed=%d error=%s", got.Status, got.CompletedHosts, got.Error)
			}
			var services int
			if err := m.pg.QueryRow(`SELECT count(*) FROM assets WHERE $1=ANY(task_ids) AND type='service' AND ip='127.0.0.1' AND port=$2`, taskID, port).Scan(&services); err != nil || services != 1 {
				t.Fatalf("persisted services=%d err=%v", services, err)
			}
			if err := m.Assets().ToggleTaskInterceptRule(taskID, allows[0].ID, false); err != nil {
				t.Fatal(err)
			}
			scanner := vaScopedScanner{pg: m.pg, taskID: taskID}
			if _, err := scanner.Scan(context.Background(), "127.0.0.1", []int{port}); err == nil {
				t.Fatal("revoked task rule allowed another host scan")
			}
			if _, err := scanner.ScanDeep(context.Background(), "127.0.0.1", []int{port}); err == nil {
				t.Fatal("revoked task rule allowed another deep check")
			}
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatal("local VA run did not finish within two minutes")
}
