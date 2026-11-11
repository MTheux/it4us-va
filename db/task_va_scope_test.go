package db

import "testing"

func TestTaskVAAllowRulesAndVAOnlyPersistence(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()
	task, err := d.CreateTaskWithOptions("VA infrastructure", "scope-bound scan", TaskCreateOptions{Name: "VA scope test", VAOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.DeleteTask(task.ID) }()
	loaded, err := d.GetTask(task.ID)
	if err != nil || loaded == nil || !loaded.VAOnly {
		t.Fatalf("VA-only marker not persisted: task=%+v err=%v", loaded, err)
	}
	store := d.Assets()
	if err := store.AddAutoScope(task.ID, "ip", "", "", "192.0.2.11"); err != nil {
		t.Fatal(err)
	}
	_, allow, err := store.TaskVAAllowRules(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateTaskIPScope([]string{"192.0.2.11"}, nil, allow); err == nil {
		t.Fatal("automatically discovered scope authorized a VA scan")
	}
	if err := store.upsertTaskScope(TaskScope{TaskID: task.ID, Kind: "cidr", Net: "198.51.100.0/28", Source: "manual"}); err != nil {
		t.Fatal(err)
	}
	_, allow, err = store.TaskVAAllowRules(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateTaskIPScope([]string{"198.51.100.4"}, nil, allow); err != nil {
		t.Fatalf("manual scope should authorize its own range: %v", err)
	}
	if err := ValidateTaskIPScope([]string{"192.0.2.11"}, nil, allow); err == nil {
		t.Fatal("manual scope authorized an unrelated discovered IP")
	}
	if _, err := store.CreateTaskInterceptRule(task.ID, "allow", "cidr", "198.51.100.0/28", "revoked", false); err != nil {
		t.Fatal(err)
	}
	_, allow, err = store.TaskVAAllowRules(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateTaskIPScope([]string{"198.51.100.4"}, nil, allow); err == nil {
		t.Fatal("disabled allow rule was bypassed by manual scope fallback")
	}
}
