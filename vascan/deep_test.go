package vascan

import (
	"context"
	"strings"
	"testing"
	"time"
)

type fixtureDeepScanner struct {
	fixtureScanner
	deepRaw   []byte
	deepCalls int
}

func (f *fixtureDeepScanner) ScanDeep(_ context.Context, target string, ports []int) ([]byte, error) {
	f.deepCalls++
	if target != "127.0.0.1" || len(ports) != 2 || ports[0] != 443 || ports[1] != 445 {
		return nil, context.DeadlineExceeded
	}
	return f.deepRaw, nil
}

func TestDeepVAUsesObservedPortsAndProducesReviewCandidates(t *testing.T) {
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	base := `<nmaprun><host><address addr="127.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port><port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds"/></port></ports></host></nmaprun>`
	deep := `<nmaprun><host><address addr="127.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><script id="ssl-cert" output="Not valid after: 2025-01-01T00:00:00"/></port><port protocol="tcp" portid="445"><script id="smb2-security-mode" output="Message signing enabled but not required"/></port></ports></host></nmaprun>`
	fake := &fixtureDeepScanner{fixtureScanner: fixtureScanner{raw: []byte(base)}, deepRaw: []byte(deep)}
	c := Campaign{Name: "lab", TaskID: 1, ApprovedBy: "operator", ExpiresAt: now.Add(time.Hour), Targets: []string{"127.0.0.1"}, Ports: []int{443, 445}, Depth: "deep"}
	result, err := Run(context.Background(), c, fake, func() time.Time { return now })
	if err != nil || fake.deepCalls != 1 {
		t.Fatalf("deep run: calls=%d err=%v", fake.deepCalls, err)
	}
	host := result.Hosts[0]
	if host.DeepError != "" || len(host.DeepChecks) != 2 {
		t.Fatalf("deep evidence missing: %+v", host)
	}
	checks := map[string]bool{}
	for _, candidate := range host.Candidates {
		checks[candidate.Check] = true
	}
	if !checks["nmap.ssl-cert"] || !checks["nmap.smb2-security-mode"] {
		t.Fatalf("expected TLS and SMB candidates, got %v", checks)
	}
}

func TestDeepVARejectsOutOfScopeEvidenceWithoutDiscardingDiscovery(t *testing.T) {
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	base := `<nmaprun><host><address addr="127.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds"/></port><port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port></ports></host></nmaprun>`
	deep := `<nmaprun><host><address addr="127.0.0.2" addrtype="ipv4"/><ports><port protocol="tcp" portid="445"><script id="smb2-security-mode" output="Message signing disabled"/></port></ports></host></nmaprun>`
	fake := &fixtureDeepScanner{fixtureScanner: fixtureScanner{raw: []byte(base)}, deepRaw: []byte(deep)}
	c := Campaign{Name: "lab", TaskID: 1, ApprovedBy: "operator", ExpiresAt: now.Add(time.Hour), Targets: []string{"127.0.0.1"}, Ports: []int{443, 445}, Depth: "deep"}
	result, err := Run(context.Background(), c, fake, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	host := result.Hosts[0]
	if host.Status != "completed" || !strings.Contains(host.DeepError, "another IP") || len(host.DeepChecks) != 0 {
		t.Fatalf("unexpected out-of-scope handling: %+v", host)
	}
	for _, candidate := range host.Candidates {
		if candidate.Check == "nmap.smb2-security-mode" {
			t.Fatal("out-of-scope deep result created a candidate")
		}
	}
}
