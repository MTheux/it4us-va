package db

import (
	"sync"
	"testing"
)

func TestAddVACandidateDeduplicatesPerTaskAndHost(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	defer d.Close()
	task, err := d.CreateTask("VA candidate dedupe", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	firstIP, err := d.Assets().UpsertIP(UpsertIPReq{IP: "127.0.0.101", TaskID: task.ID})
	if err != nil {
		t.Fatal(err)
	}
	secondIP, err := d.Assets().UpsertIP(UpsertIPReq{IP: "127.0.0.102", TaskID: task.ID})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = d.Exec(`DELETE FROM assets WHERE id IN ($1,$2)`, firstIP, secondIP)
	}()
	add := func(ipID int64) (int64, bool) {
		id, created, err := d.AddVACandidate(task.ID, ipID, "exposicao-de-servico", "FTP (porta 21/tcp)", SeverityHigh,
			"summary", "evidence", []int64{ipID})
		if err != nil {
			t.Fatal(err)
		}
		return id, created
	}
	first, created := add(firstIP)
	if !created {
		t.Fatal("first candidate was not created")
	}
	defer d.DeleteFinding(first)
	second, created := add(firstIP)
	if created || second != first {
		t.Fatal("same host and task produced a duplicate")
	}
	var group sync.WaitGroup
	for range 8 {
		group.Add(1)
		go func() {
			defer group.Done()
			id, created, err := d.AddVACandidate(task.ID, firstIP, "exposicao-de-servico", "FTP (porta 21/tcp)", SeverityHigh,
				"summary", "evidence", []int64{firstIP})
			if err != nil || created || id != first {
				t.Errorf("concurrent scan duplicated candidate: id=%d created=%t err=%v", id, created, err)
			}
		}()
	}
	group.Wait()
	third, created := add(secondIP)
	if !created || third == first {
		t.Fatal("distinct host was incorrectly deduplicated")
	}
	defer d.DeleteFinding(third)
}
