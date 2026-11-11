package vascan

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/MTheux/it4us-va/db"
	"github.com/MTheux/it4us-va/vacheck"
)

// DeepScanner runs only two fixed read-only NSE scripts on services that were
// already observed by the first scan. It cannot select targets or scripts.
type DeepScanner interface {
	ScanDeep(context.Context, string, []int) ([]byte, error)
}

type DeepObservation struct {
	Port   int    `json:"port"`
	Script string `json:"script"`
	Output string `json:"output"`
}

var deepTLSDefaults = map[int]bool{443: true, 465: true, 636: true, 993: true, 995: true, 8443: true, 5986: true}

func selectDeepPorts(services []vacheck.Asset) ([]int, bool) {
	ports := map[int]bool{}
	for _, service := range services {
		name := strings.ToLower(service.Service)
		if service.Port == 445 || name == "microsoft-ds" || deepTLSDefaults[service.Port] || strings.Contains(name, "ssl") || strings.Contains(name, "https") || strings.Contains(name, "tls") {
			ports[service.Port] = true
		}
	}
	out := make([]int, 0, len(ports))
	for port := range ports {
		out = append(out, port)
	}
	sort.Ints(out)
	if len(out) > 32 {
		return out[:32], true
	}
	return out, false
}

func (s NmapScanner) ScanDeep(ctx context.Context, target string, ports []int) ([]byte, error) {
	if net.ParseIP(target) == nil || len(ports) == 0 || len(ports) > 32 {
		return nil, errors.New("deep VA needs one literal IP and 1 to 32 observed ports")
	}
	portSpec, err := formatPortSpec(ports)
	if err != nil {
		return nil, err
	}
	bin := s.Binary
	if bin == "" {
		bin = "nmap"
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin,
		"-sT", "-Pn", "-n", "--max-retries", "1", "--host-timeout", "150s",
		"--script-timeout", "20s", "--script", "ssl-cert,smb2-security-mode",
		"-p", portSpec, "-oX", "-", "--", target)
	var stdout, stderr boundedBuffer
	stdout.limit, stderr.limit = maxScannerOutput, 2048
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("deep nmap failed: %w (%s)", err, strings.TrimSpace(stderr.String()))
	}
	if stdout.exceeded {
		return nil, errors.New("deep nmap output exceeded 8 MiB")
	}
	return stdout.Bytes(), nil
}

type deepNmapRun struct {
	Hosts []struct {
		Addresses []struct {
			Addr string `xml:"addr,attr"`
		} `xml:"address"`
		Ports []struct {
			Port    int `xml:"portid,attr"`
			Scripts []struct {
				ID     string `xml:"id,attr"`
				Output string `xml:"output,attr"`
			} `xml:"script"`
		} `xml:"ports>port"`
	} `xml:"host"`
}

var certExpiryPattern = regexp.MustCompile(`(?i)Not valid after:\s*(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)`)

func parseDeepResult(raw []byte, target string, plannedPorts []int, prior []vacheck.Candidate, now time.Time) ([]DeepObservation, []vacheck.Candidate, error) {
	var run deepNmapRun
	if err := xml.Unmarshal(raw, &run); err != nil {
		return nil, prior, fmt.Errorf("deep nmap XML invalid: %w", err)
	}
	allowed := map[int]bool{}
	for _, port := range plannedPorts {
		allowed[port] = true
	}
	observations := []DeepObservation{}
	candidates := append([]vacheck.Candidate(nil), prior...)
	foundTarget := false
	for _, host := range run.Hosts {
		match := false
		for _, addr := range host.Addresses {
			if net.ParseIP(addr.Addr) != nil && net.ParseIP(target).Equal(net.ParseIP(addr.Addr)) {
				match = true
			} else if net.ParseIP(addr.Addr) != nil {
				return nil, prior, fmt.Errorf("deep nmap output contains another IP")
			}
		}
		if !match {
			continue
		}
		foundTarget = true
		for _, port := range host.Ports {
			if !allowed[port.Port] {
				return nil, prior, fmt.Errorf("deep nmap output contains an unplanned port")
			}
			for _, script := range port.Scripts {
				if script.ID != "ssl-cert" && script.ID != "smb2-security-mode" {
					continue
				}
				fullOutput := strings.ToValidUTF8(strings.TrimSpace(script.Output), "")
				output := fullOutput
				if len(output) > 1024 {
					output = output[:1024]
				}
				observations = append(observations, DeepObservation{Port: port.Port, Script: script.ID, Output: output})
				asset := vacheck.Asset{IP: target, Port: port.Port, Proto: "tcp"}
				if script.ID == "ssl-cert" {
					if m := certExpiryPattern.FindStringSubmatch(fullOutput); len(m) == 2 {
						if expiry, err := time.Parse("2006-01-02T15:04:05", m[1]); err == nil && expiry.Before(now) {
							candidates = append(candidates, vacheck.Candidate{Check: "nmap.ssl-cert", Title: fmt.Sprintf("Certificado TLS expirado em %s:%d", target, port.Port), VulnClass: "tls-certificado-expirado", Severity: db.SeverityMedium, Asset: asset, Summary: "O certificado apresentado pelo serviço expirou; revisar nome, cadeia e renovação antes de concluir impacto.", Evidence: "Not valid after: " + m[1] + "\n" + output, Tags: []string{"foresea:pki"}})
						}
					}
				} else if strings.Contains(strings.ToLower(fullOutput), "message signing enabled but not required") || strings.Contains(strings.ToLower(fullOutput), "message signing disabled") {
					candidates = append(candidates, vacheck.Candidate{Check: "nmap.smb2-security-mode", Title: fmt.Sprintf("Assinatura SMB não obrigatória em %s:%d", target, port.Port), VulnClass: "smb-assinatura-opcional", Severity: db.SeverityMedium, Asset: asset, Summary: "O serviço SMB informou que a assinatura não é obrigatória; validar a política por dialeto e o impacto na rede.", Evidence: "SMB signing not required\n" + output, Tags: []string{"foresea:shares"}})
				}
			}
		}
	}
	if !foundTarget {
		return nil, prior, errors.New("deep nmap output does not contain the planned target")
	}
	return observations, candidates, nil
}
