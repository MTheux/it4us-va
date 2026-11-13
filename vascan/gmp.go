package vascan

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/MTheux/it4us-va/vacheck"
)

// GMPConfig controls an optional VT manager. Only the local, loopback bridge
// is accepted; the credential is injected at runtime and never persisted here.
type GMPConfig struct {
	Address   string
	Username  string
	Password  string
	ConfigID  string
	ScannerID string
}

var gmpUUID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func (c GMPConfig) Validate() error {
	host, _, err := net.SplitHostPort(c.Address)
	if err != nil || host != "127.0.0.1" {
		return errors.New("VT manager must use a loopback TCP bridge")
	}
	if c.Username == "" || c.Password == "" || !gmpUUID.MatchString(c.ConfigID) || !gmpUUID.MatchString(c.ScannerID) {
		return errors.New("VT manager credentials, config and scanner IDs are required")
	}
	return nil
}

type gmpResponse struct {
	XMLName xml.Name
	Status  int    `xml:"status,attr"`
	ID      string `xml:"id,attr"`
	Inner   string `xml:",innerxml"`
}

type gmpSession struct {
	conn net.Conn
}

func gmpEscape(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

func openGMPSession(ctx context.Context, cfg GMPConfig) (*gmpSession, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("VT manager unavailable: %w", err)
	}
	s := &gmpSession{conn: conn}
	_, err = s.call(ctx, "<authenticate><credentials><username>"+gmpEscape(cfg.Username)+"</username><password>"+gmpEscape(cfg.Password)+"</password></credentials></authenticate>")
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("VT manager authentication failed: %w", err)
	}
	return s, nil
}

func GMPHealth(ctx context.Context, cfg GMPConfig) error {
	s, err := openGMPSession(ctx, cfg)
	if err != nil {
		return err
	}
	defer s.conn.Close()
	for _, check := range []struct {
		command string
		item    string
		id      string
	}{
		{"<get_configs config_id=\"" + cfg.ConfigID + "\" details=\"1\"/>", "config", cfg.ConfigID},
		{"<get_scanners scanner_id=\"" + cfg.ScannerID + "\"/>", "scanner", cfg.ScannerID},
	} {
		response, err := s.call(ctx, check.command)
		if err != nil {
			return err
		}
		var item struct {
			ID       string `xml:"id,attr"`
			Name     string `xml:"name"`
			Families []struct {
				Name string `xml:"name"`
			} `xml:"families>family"`
			Preferences []struct {
				Name  string `xml:"name"`
				Value string `xml:"value"`
			} `xml:"preferences>preference"`
		}
		var found bool
		decoder := xml.NewDecoder(strings.NewReader("<items>" + response.Inner + "</items>"))
		for {
			token, err := decoder.Token()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return err
			}
			start, ok := token.(xml.StartElement)
			if !ok || start.Name.Local != check.item {
				continue
			}
			if err := decoder.DecodeElement(&item, &start); err != nil {
				return err
			}
			found = item.ID == check.id
			break
		}
		if !found {
			return fmt.Errorf("VT manager %s unavailable", check.item)
		}
		if check.item == "config" {
			if item.Name != "IT4US Infra Only v2" {
				return errors.New("VT manager requires the bounded infrastructure profile")
			}
			safe := false
			for _, preference := range item.Preferences {
				if preference.Name == "safe_checks" && preference.Value == "1" {
					safe = true
				}
			}
			if !safe {
				return errors.New("VT manager safe_checks is disabled")
			}
			allowed := map[string]bool{
				"CISCO": true, "Databases": true, "F5 Local Security Checks": true,
				"FTP": true, "FortiOS Local Security Checks": true, "Huawei": true,
				"JunOS Local Security Checks": true, "Palo Alto PAN-OS Local Security Checks": true,
				"RPC": true, "Remote file access": true,
				"SMTP problems": true, "SNMP": true, "SSL and TLS": true,
				"Service detection": true, "Settings": true, "Useless services": true,
				"Windows": true,
			}
			if len(item.Families) != len(allowed) {
				return errors.New("VT manager profile family selection changed")
			}
			for _, family := range item.Families {
				if !allowed[family.Name] {
					return errors.New("VT manager profile includes an unapproved family")
				}
			}
		}
	}
	return nil
}

func (s *gmpSession) call(ctx context.Context, command string) (gmpResponse, error) {
	deadline := time.Now().Add(30 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := s.conn.SetDeadline(deadline); err != nil {
		return gmpResponse{}, err
	}
	stop := context.AfterFunc(ctx, func() { _ = s.conn.Close() })
	defer stop()
	if _, err := io.WriteString(s.conn, command); err != nil {
		return gmpResponse{}, err
	}
	var response gmpResponse
	dec := xml.NewDecoder(io.LimitReader(s.conn, 8<<20))
	if err := dec.Decode(&response); err != nil {
		return gmpResponse{}, err
	}
	if response.Status < 200 || response.Status >= 300 {
		return gmpResponse{}, fmt.Errorf("VT manager rejected %s (status %d)", response.XMLName.Local, response.Status)
	}
	return response, nil
}

// GMPHostReport is one manager report associated with exactly one approved IP.
type GMPHostReport struct {
	Raw        []byte
	Candidates []vacheck.Candidate
	ReportID   string
}

// GMPScanHost creates a one-host task, polls it and stops it when the campaign
// context ends. The caller must recheck task scope before calling this method.
func GMPScanHost(ctx context.Context, cfg GMPConfig, target string, ports []int, runID string, progress func(string) error) (GMPHostReport, error) {
	ip, err := netip.ParseAddr(target)
	if err != nil || ip.Is4In6() || ip.String() != target {
		return GMPHostReport{}, errors.New("VT target must be a canonical literal IP")
	}
	if len(runID) != 24 {
		return GMPHostReport{}, errors.New("invalid VA run ID")
	}
	portSpec, err := formatPortSpec(ports)
	if err != nil {
		return GMPHostReport{}, err
	}
	s, err := openGMPSession(ctx, cfg)
	if err != nil {
		return GMPHostReport{}, err
	}
	defer s.conn.Close()
	name := "IT4US-VA-" + runID + "-" + strings.ReplaceAll(target, ":", "_")
	createTarget := "<create_target><name>" + gmpEscape(name) + "</name><hosts>" + gmpEscape(target) + "</hosts><port_range>T:" + portSpec + "</port_range><alive_tests><alive_test>Consider Alive</alive_test></alive_tests></create_target>"
	response, err := s.call(ctx, createTarget)
	if err != nil {
		return GMPHostReport{}, err
	}
	targetID := response.ID
	if !gmpUUID.MatchString(targetID) {
		return GMPHostReport{}, errors.New("VT manager returned invalid target ID")
	}
	createTask := "<create_task><name>" + gmpEscape(name) + "</name><config id=\"" + cfg.ConfigID + "\"/><target id=\"" + targetID + "\"/><scanner id=\"" + cfg.ScannerID + "\"/></create_task>"
	response, err = s.call(ctx, createTask)
	if err != nil {
		return GMPHostReport{}, err
	}
	taskID := response.ID
	if !gmpUUID.MatchString(taskID) {
		return GMPHostReport{}, errors.New("VT manager returned invalid task ID")
	}
	started, completed := false, false
	defer func() {
		if !started || completed {
			return
		}
		stopCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if stopSession, err := openGMPSession(stopCtx, cfg); err == nil {
			_, _ = stopSession.call(stopCtx, "<stop_task task_id=\""+taskID+"\"/>")
			stopSession.conn.Close()
		}
	}()
	// Once start is sent, a timeout may hide a task that actually started.
	// Arm the remote stop before the request so cancellation still stops it.
	started = true
	response, err = s.call(ctx, "<start_task task_id=\""+taskID+"\"/>")
	if err != nil {
		return GMPHostReport{}, err
	}
	var start struct {
		ReportID string `xml:"report_id"`
	}
	if err := xml.Unmarshal([]byte("<start>"+response.Inner+"</start>"), &start); err != nil || !gmpUUID.MatchString(start.ReportID) {
		return GMPHostReport{}, errors.New("VT manager returned invalid report ID")
	}
	if progress != nil {
		if err := progress("started"); err != nil {
			return GMPHostReport{}, err
		}
	}
	for {
		if err := ctx.Err(); err != nil {
			return GMPHostReport{}, err
		}
		response, err = s.call(ctx, "<get_tasks task_id=\""+taskID+"\"/>")
		if err != nil {
			return GMPHostReport{}, err
		}
		var state struct {
			Task struct {
				Status   string `xml:"status"`
				Progress string `xml:"progress"`
			} `xml:"task"`
		}
		if err := xml.Unmarshal([]byte("<tasks>"+response.Inner+"</tasks>"), &state); err != nil {
			return GMPHostReport{}, err
		}
		if progress != nil {
			if err := progress(strings.TrimSpace(state.Task.Status) + " " + strings.TrimSpace(state.Task.Progress)); err != nil {
				return GMPHostReport{}, err
			}
		}
		switch strings.TrimSpace(state.Task.Status) {
		case "Done":
			response, err = s.call(ctx, "<get_reports report_id=\""+start.ReportID+"\" details=\"1\" ignore_pagination=\"1\"/>")
			if err != nil {
				return GMPHostReport{}, err
			}
			raw := []byte("<get_reports_response status=\"200\">" + response.Inner + "</get_reports_response>")
			candidates, err := ParseGMPReport(raw, target)
			if err != nil {
				return GMPHostReport{}, err
			}
			approvedPorts := make(map[int]bool, len(ports))
			for _, port := range ports {
				approvedPorts[port] = true
			}
			for _, candidate := range candidates {
				if !approvedPorts[candidate.Asset.Port] {
					return GMPHostReport{}, fmt.Errorf("VT result outside observed port %d", candidate.Asset.Port)
				}
			}
			completed = true
			return GMPHostReport{Raw: raw, Candidates: candidates, ReportID: start.ReportID}, nil
		case "Stopped", "Interrupted", "Stop Requested":
			return GMPHostReport{}, fmt.Errorf("VT task stopped: %s", state.Task.Status)
		case "Running", "Requested", "Queued", "New":
		default:
			return GMPHostReport{}, fmt.Errorf("VT task entered unexpected state %q", state.Task.Status)
		}
		timer := time.NewTimer(10 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return GMPHostReport{}, ctx.Err()
		case <-timer.C:
		}
	}
}

// ParseGMPReport treats every VT result as a pending candidate. A report may
// contain host/port data outside the requested target; that is rejected.
func ParseGMPReport(raw []byte, target string) ([]vacheck.Candidate, error) {
	if len(raw) > 8<<20 {
		return nil, errors.New("VT report exceeds 8 MiB")
	}
	dec := xml.NewDecoder(bytes.NewReader(raw))
	out := make([]vacheck.Candidate, 0)
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		start, ok := tok.(xml.StartElement)
		if !ok || start.Name.Local != "result" {
			continue
		}
		var row struct {
			Host        string `xml:"host"`
			Port        string `xml:"port"`
			Name        string `xml:"name"`
			Description string `xml:"description"`
			Severity    string `xml:"severity"`
			QoD         struct {
				Value string `xml:"value"`
			} `xml:"qod"`
			NVT struct {
				OID  string `xml:"oid,attr"`
				Name string `xml:"name"`
				CVE  string `xml:"cve"`
			} `xml:"nvt"`
		}
		if err := dec.DecodeElement(&row, &start); err != nil {
			return nil, err
		}
		if strings.TrimSpace(row.Host) != target {
			return nil, fmt.Errorf("VT report result outside target %s", target)
		}
		severity, err := strconv.ParseFloat(strings.TrimSpace(row.Severity), 64)
		if err != nil || severity < 1 {
			continue
		}
		qod, _ := strconv.Atoi(strings.TrimSpace(row.QoD.Value))
		if qod < 70 {
			continue
		}
		port, proto := 0, "tcp"
		if parts := strings.SplitN(strings.TrimSpace(row.Port), "/", 2); len(parts) == 2 {
			port, _ = strconv.Atoi(parts[0])
			proto = parts[1]
		}
		if port < 1 || port > 65535 || proto != "tcp" {
			continue
		}
		level := "low"
		switch {
		case severity >= 9:
			level = "critical"
		case severity >= 7:
			level = "high"
		case severity >= 4:
			level = "medium"
		}
		name := strings.TrimSpace(row.Name)
		if name == "" {
			name = strings.TrimSpace(row.NVT.Name)
		}
		if name == "" {
			continue
		}
		description := strings.TrimSpace(row.Description)
		if len(description) > 2000 {
			description = description[:2000]
		}
		evidence := fmt.Sprintf("VT %s; QoD %d; severity %.1f; port %s", row.NVT.OID, qod, severity, row.Port)
		candidate := vacheck.Candidate{Check: "gmp.vt", Title: name, VulnClass: "infra-vt", Severity: level, Asset: vacheck.Asset{IP: target, Port: port, Proto: "tcp", Service: "unknown"}, Summary: description, Evidence: evidence}
		if cve := strings.TrimSpace(row.NVT.CVE); strings.HasPrefix(cve, "CVE-") {
			candidate.Refs = []string{cve}
		}
		out = append(out, candidate)
		if len(out) >= 2000 {
			return nil, errors.New("VT report result limit exceeded")
		}
	}
	return out, nil
}
