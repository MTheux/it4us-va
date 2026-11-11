package vascan

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fixtureScanner struct {
	calls []string
	raw   []byte
	err   map[string]error
}

func (f *fixtureScanner) Scan(_ context.Context, target string, _ []int) ([]byte, error) {
	f.calls = append(f.calls, target)
	if err := f.err[target]; err != nil {
		return nil, err
	}
	return f.raw, nil
}

func TestCampaignRejectsInvalidScopeBeforeScannerRuns(t *testing.T) {
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	base := Campaign{Name: "lab", TaskID: 1, ApprovedBy: "operator", ExpiresAt: now.Add(time.Hour), Targets: []string{"127.0.0.1"}, Ports: []int{443}}
	for _, tc := range []struct {
		name   string
		change func(*Campaign)
	}{
		{"expired", func(c *Campaign) { c.ExpiresAt = now }},
		{"hostname", func(c *Campaign) { c.Targets = []string{"example.com"} }},
		{"uncanonical cidr", func(c *Campaign) { c.Targets = []string{"127.0.0.1/24"} }},
		{"oversized cidr", func(c *Campaign) { c.Targets = []string{"10.0.0.0/16"} }},
		{"overlapping range", func(c *Campaign) { c.Targets = []string{"127.0.0.0/30", "127.0.0.1"} }},
		{"duplicate", func(c *Campaign) { c.Targets = []string{"127.0.0.1", "127.0.0.1"} }},
		{"port", func(c *Campaign) { c.Ports = []int{0} }},
		{"no approval", func(c *Campaign) { c.ApprovedBy = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := base
			tc.change(&c)
			fake := &fixtureScanner{}
			if _, err := Run(context.Background(), c, fake, func() time.Time { return now }); err == nil {
				t.Fatal("expected rejection")
			}
			if len(fake.calls) != 0 {
				t.Fatal("scanner called with invalid campaign")
			}
		})
	}
}

func TestCampaignExpandsCIDRIntoExactScannerTargets(t *testing.T) {
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	c := Campaign{Name: "lab", TaskID: 1, ApprovedBy: "soc", ExpiresAt: now.Add(time.Hour), Targets: []string{"127.0.0.0/30"}, Ports: []int{443}}
	targets, err := c.ExpandedTargets()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"127.0.0.0", "127.0.0.1", "127.0.0.2", "127.0.0.3"}
	if strings.Join(targets, ",") != strings.Join(want, ",") {
		t.Fatalf("expanded %v, want %v", targets, want)
	}
	fake := &fixtureScanner{err: map[string]error{}}
	for _, target := range targets {
		fake.err[target] = errors.New("fixture no network")
	}
	progress := make([]string, 0, len(want))
	result, err := RunWithProgress(context.Background(), c, fake, func() time.Time { return now }, func(host HostResult) {
		progress = append(progress, host.Target)
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(fake.calls, ",") != strings.Join(want, ",") || strings.Join(progress, ",") != strings.Join(want, ",") || len(result.Hosts) != len(want) {
		t.Fatalf("scanner calls %v, progress %v, hosts %d", fake.calls, progress, len(result.Hosts))
	}
}

func TestRunRecordsCoverageAndHostFailure(t *testing.T) {
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	raw := []byte(`<nmaprun><host><address addr="127.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="21"><state state="open"/><service name="ftp"/></port></ports></host></nmaprun>`)
	c := Campaign{Name: "fixture", TaskID: 1, ApprovedBy: "soc", ExpiresAt: now.Add(time.Hour), Targets: []string{"127.0.0.1", "127.0.0.2"}, Ports: []int{445}}
	fake := &fixtureScanner{raw: raw, err: map[string]error{"127.0.0.2": errors.New("scanner unavailable")}}
	r, err := Run(context.Background(), c, fake, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if len(fake.calls) != 2 || len(r.Hosts) != 2 {
		t.Fatalf("calls=%v hosts=%d", fake.calls, len(r.Hosts))
	}
	if r.Hosts[0].Status != "completed" || r.Hosts[0].SHA256 == "" || len(r.Hosts[0].Candidates) == 0 {
		t.Fatalf("first host: %+v", r.Hosts[0])
	}
	if r.Hosts[1].Status != "failed" || !strings.Contains(r.Hosts[1].Error, "unavailable") {
		t.Fatalf("second host: %+v", r.Hosts[1])
	}
}

func TestRunRejectsOutOfTargetScannerOutput(t *testing.T) {
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	c := Campaign{Name: "lab", TaskID: 1, ApprovedBy: "soc", ExpiresAt: now.Add(time.Hour), Targets: []string{"127.0.0.1"}, Ports: []int{21}}
	fake := &fixtureScanner{raw: []byte(`<nmaprun><host><address addr="127.0.0.2" addrtype="ipv4"/><ports><port protocol="tcp" portid="21"><state state="open"/><service name="ftp"/></port></ports></host></nmaprun>`)}
	r, err := Run(context.Background(), c, fake, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if r.Hosts[0].Status != "failed" || len(r.Hosts[0].Candidates) != 0 {
		t.Fatalf("out-of-target data accepted: %+v", r.Hosts[0])
	}
}

func TestLoadCampaignRejectsTrailingData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "campaign.json")
	data := `{"name":"lab","task_id":1,"approved_by":"soc","expires_at":"2099-01-01T00:00:00Z","targets":["127.0.0.1"],"ports":[443]} {}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCampaign(path, time.Now()); err == nil {
		t.Fatal("accepted trailing JSON")
	}
}
