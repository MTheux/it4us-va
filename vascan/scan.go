// Package vascan runs repeatable infrastructure VA checks for one approved campaign.
// The scanner receives only literal IPs expanded from the campaign; the AI agent can
// review candidates later, but cannot change scanner arguments or add targets.
package vascan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/MTheux/it4us-va/vacheck"
)

const maxTargets = 4096
const maxScannerOutput = 8 << 20
const maxPortHostChecks = 4_096_000

// Campaign is created once by the SOC for a scan window. It intentionally has
// few fields so the operator does not have to approve every individual check.
type Campaign struct {
	Name        string    `json:"name"`
	TaskID      int64     `json:"task_id"`
	ApprovedBy  string    `json:"approved_by"`
	ExpiresAt   time.Time `json:"expires_at"`
	Targets     []string  `json:"targets"`
	PortProfile string    `json:"port_profile,omitempty"`
	Ports       []int     `json:"ports"`
}

func LoadCampaign(path string, now time.Time) (Campaign, error) {
	f, err := os.Open(path)
	if err != nil {
		return Campaign{}, err
	}
	defer f.Close()
	dec := json.NewDecoder(io.LimitReader(f, 64<<10))
	dec.DisallowUnknownFields()
	var c Campaign
	if err := dec.Decode(&c); err != nil {
		return Campaign{}, fmt.Errorf("campaign JSON: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return Campaign{}, errors.New("campaign JSON contains trailing data")
	}
	if err := c.Validate(now); err != nil {
		return Campaign{}, err
	}
	return c, nil
}

func (c Campaign) Validate(now time.Time) error {
	if strings.TrimSpace(c.Name) == "" || strings.TrimSpace(c.ApprovedBy) == "" || c.TaskID <= 0 {
		return errors.New("campaign name, task_id and approved_by are required")
	}
	if c.ExpiresAt.IsZero() || !now.Before(c.ExpiresAt) {
		return errors.New("campaign approval has expired")
	}
	targets, err := c.ExpandedTargets()
	if err != nil {
		return err
	}
	if c.PortProfile == "all" {
		if len(c.Ports) != 0 {
			return errors.New("all-port profile cannot include a custom port list")
		}
		if len(targets)*65535 > maxPortHostChecks {
			return fmt.Errorf("all-port campaign exceeds the %d port-host check budget", maxPortHostChecks)
		}
		return nil
	}
	if c.PortProfile != "" && c.PortProfile != "custom" {
		return fmt.Errorf("unsupported port profile %q", c.PortProfile)
	}
	if len(c.Ports) == 0 || len(c.Ports) > 1000 {
		return errors.New("campaign needs 1 to 1000 TCP ports")
	}
	ports := make(map[int]bool, len(c.Ports))
	for _, p := range c.Ports {
		if p < 1 || p > 65535 || ports[p] {
			return fmt.Errorf("invalid or duplicate TCP port %d", p)
		}
		ports[p] = true
	}
	return nil
}

func (c Campaign) PortCount() int {
	if c.PortProfile == "all" {
		return 65535
	}
	return len(c.Ports)
}

func (c Campaign) scannerPorts() []int {
	if c.PortProfile != "all" {
		return c.Ports
	}
	ports := make([]int, 65535)
	for i := range ports {
		ports[i] = i + 1
	}
	return ports
}

// ExpandedTargets resolves literal IPs and CIDR ranges into the exact host list
// shown in the plan and passed to the scanner. DNS names are never resolved.
func (c Campaign) ExpandedTargets() ([]string, error) {
	if len(c.Targets) == 0 || len(c.Targets) > maxTargets {
		return nil, fmt.Errorf("campaign needs 1 to %d IPs or CIDR ranges", maxTargets)
	}
	out := make([]string, 0, len(c.Targets))
	seen := make(map[string]bool)
	for _, raw := range c.Targets {
		if strings.TrimSpace(raw) != raw || strings.Contains(raw, "%") {
			return nil, fmt.Errorf("invalid target %q", raw)
		}
		if ip, err := netip.ParseAddr(raw); err == nil {
			if ip.Is4In6() {
				return nil, fmt.Errorf("ambiguous IPv4-mapped target %q", raw)
			}
			if seen[ip.String()] {
				return nil, fmt.Errorf("duplicate target %q", raw)
			}
			seen[ip.String()] = true
			out = append(out, ip.String())
			continue
		}
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || prefix.Addr().Is4In6() || prefix != prefix.Masked() {
			return nil, fmt.Errorf("target %q must be a literal IP or canonical CIDR range", raw)
		}
		for ip := prefix.Addr(); prefix.Contains(ip); ip = ip.Next() {
			if len(out) >= maxTargets {
				return nil, fmt.Errorf("campaign exceeds %d expanded IP targets", maxTargets)
			}
			if seen[ip.String()] {
				return nil, fmt.Errorf("duplicate target %q in %q", ip, raw)
			}
			seen[ip.String()] = true
			out = append(out, ip.String())
		}
	}
	return out, nil
}

// Scanner is replaceable with a fixture in tests. Implementations return Nmap XML.
type Scanner interface {
	Scan(context.Context, string, []int) ([]byte, error)
}

type NmapScanner struct {
	Binary      string
	HostTimeout time.Duration
}

func (s NmapScanner) Scan(ctx context.Context, target string, ports []int) ([]byte, error) {
	if net.ParseIP(target) == nil {
		return nil, errors.New("scanner target is not a literal IP")
	}
	portSpec, err := formatPortSpec(ports)
	if err != nil {
		return nil, err
	}
	bin := s.Binary
	if bin == "" {
		bin = "nmap"
	}
	timeout := s.HostTimeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
		if len(ports) > 1000 {
			timeout = 20 * time.Minute
		}
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// Fixed arguments, no shell, no NSE scripts, no exploit or credential checks.
	cmd := exec.CommandContext(ctx, bin, "-sT", "-sV", "-Pn", "-n", "--max-retries", "1", "--host-timeout", strconv.Itoa(int(timeout.Seconds()))+"s", "-p", portSpec, "-oX", "-", "--", target)
	var stdout, stderr boundedBuffer
	stdout.limit, stderr.limit = maxScannerOutput, 2048
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("nmap failed: %w (%s)", err, strings.TrimSpace(stderr.String()))
	}
	if stdout.exceeded {
		return nil, errors.New("nmap output exceeded 8 MiB")
	}
	return stdout.Bytes(), nil
}

func formatPortSpec(ports []int) (string, error) {
	if len(ports) == 0 {
		return "", errors.New("scanner needs ports")
	}
	ps := append([]int(nil), ports...)
	sort.Ints(ps)
	parts := make([]string, 0, len(ps))
	for i, p := range ps {
		if p < 1 || p > 65535 {
			return "", fmt.Errorf("invalid port %d", p)
		}
		if i > 0 && p == ps[i-1] {
			return "", fmt.Errorf("duplicate port %d", p)
		}
	}
	for start := 0; start < len(ps); {
		end := start
		for end+1 < len(ps) && ps[end+1] == ps[end]+1 {
			end++
		}
		part := strconv.Itoa(ps[start])
		if end > start {
			part += "-" + strconv.Itoa(ps[end])
		}
		parts = append(parts, part)
		start = end + 1
	}
	return strings.Join(parts, ","), nil
}

type boundedBuffer struct {
	bytes.Buffer
	limit    int
	exceeded bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.limit {
		b.exceeded = true
		return 0, errors.New("output limit exceeded")
	}
	return b.Buffer.Write(p)
}

type HostResult struct {
	Target     string              `json:"target"`
	Status     string              `json:"status"`
	SHA256     string              `json:"scanner_output_sha256,omitempty"`
	Services   []vacheck.Asset     `json:"services,omitempty"`
	Candidates []vacheck.Candidate `json:"candidates"`
	Error      string              `json:"error,omitempty"`
}
type Result struct {
	Campaign   string       `json:"campaign"`
	StartedAt  time.Time    `json:"started_at"`
	FinishedAt time.Time    `json:"finished_at"`
	Hosts      []HostResult `json:"hosts"`
}

// Run continues after a host failure but stops immediately when the campaign
// expires or the operator cancels. A completed host with no candidates is not
// silently treated as a vulnerability-free host; the result records coverage.
func Run(ctx context.Context, c Campaign, scanner Scanner, now func() time.Time) (Result, error) {
	return RunWithProgress(ctx, c, scanner, now, nil)
}

// RunWithProgress reports each completed host check without changing scanner
// scope. Callbacks should return quickly; they run in the scan goroutine.
func RunWithProgress(ctx context.Context, c Campaign, scanner Scanner, now func() time.Time, onHost func(HostResult)) (Result, error) {
	if now == nil {
		now = time.Now
	}
	if err := c.Validate(now()); err != nil {
		return Result{}, err
	}
	if scanner == nil {
		return Result{}, errors.New("scanner is required")
	}
	targets, _ := c.ExpandedTargets() // Validate above established the expansion.
	ports := c.scannerPorts()
	r := Result{Campaign: c.Name, StartedAt: now(), Hosts: make([]HostResult, 0, len(targets))}
	for _, target := range targets {
		if err := ctx.Err(); err != nil {
			r.FinishedAt = now()
			return r, err
		}
		if !now().Before(c.ExpiresAt) {
			r.FinishedAt = now()
			return r, errors.New("campaign expired during scan")
		}
		h := HostResult{Target: target, Status: "failed", Candidates: []vacheck.Candidate{}}
		hostCtx, cancel := context.WithDeadline(ctx, c.ExpiresAt)
		raw, err := scanner.Scan(hostCtx, target, ports)
		cancel()
		if err == nil {
			sum := sha256.Sum256(raw)
			h.SHA256 = hex.EncodeToString(sum[:])
			h.Candidates, err = vacheck.ParseNmap(raw)
			if err == nil {
				h.Services, err = vacheck.ParseNmapInventory(raw)
			}
			if h.Candidates == nil {
				h.Candidates = []vacheck.Candidate{}
			}
			if err == nil {
				for _, service := range h.Services {
					if service.IP == "" || !net.ParseIP(target).Equal(net.ParseIP(service.IP)) {
						err = fmt.Errorf("scanner output contains a service outside target %s", target)
						h.Services = nil
						h.Candidates = []vacheck.Candidate{}
						break
					}
				}
			}
			if err == nil {
				for _, candidate := range h.Candidates {
					if candidate.Asset.IP == "" || !net.ParseIP(target).Equal(net.ParseIP(candidate.Asset.IP)) {
						err = fmt.Errorf("scanner output contains a candidate outside target %s", target)
						h.Candidates = []vacheck.Candidate{}
						break
					}
				}
			}
		}
		if err != nil {
			h.Error = err.Error()
		} else {
			h.Status = "completed"
		}
		r.Hosts = append(r.Hosts, h)
		if onHost != nil {
			onHost(h)
		}
	}
	r.FinishedAt = now()
	return r, nil
}
