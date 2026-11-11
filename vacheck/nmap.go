package vacheck

import (
	"encoding/xml"
	"fmt"
	"strings"

	"github.com/MTheux/it4us-va/db"
)

func init() {
	Register(Check{
		ID:           "nmap.service",
		Title:        "Descoberta de serviços (nmap -sV)",
		Tool:         "nmap",
		ReadOnlyArgs: []string{"-sV", "-Pn", "-oX", "-"},
		ForeSea:      "descoberta de rede/serviços",
		Parse:        ParseNmap,
	})
}

// nmap -oX XML, minimal subset.
type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
	Addresses []nmapAddr `xml:"address"`
	Hostnames []struct {
		Name string `xml:"name,attr"`
	} `xml:"hostnames>hostname"`
	Ports []nmapPort `xml:"ports>port"`
}

type nmapAddr struct {
	Addr string `xml:"addr,attr"`
	Type string `xml:"addrtype,attr"`
}

type nmapPort struct {
	Protocol string `xml:"protocol,attr"`
	PortID   int    `xml:"portid,attr"`
	State    struct {
		State string `xml:"state,attr"`
	} `xml:"state"`
	Service struct {
		Name    string   `xml:"name,attr"`
		Product string   `xml:"product,attr"`
		Version string   `xml:"version,attr"`
		CPE     []string `xml:"cpe"`
	} `xml:"service"`
}

// ParseNmapInventory keeps every open service for later CVE applicability
// checks without promoting each open port to an Achados candidate.
func ParseNmapInventory(raw []byte) ([]Asset, error) {
	var run nmapRun
	if err := xml.Unmarshal(raw, &run); err != nil {
		return nil, fmt.Errorf("vacheck: XML do nmap invalido: %w", err)
	}
	var out []Asset
	for _, h := range run.Hosts {
		ip := ""
		for _, a := range h.Addresses {
			if a.Type == "ipv4" || a.Type == "ipv6" {
				ip = a.Addr
			}
		}
		for _, p := range h.Ports {
			if p.State.State == "open" {
				out = append(out, Asset{IP: ip, Port: p.PortID, Proto: p.Protocol, Service: p.Service.Name, Product: p.Service.Product, Version: p.Service.Version, CPE: p.Service.CPE})
			}
		}
	}
	return out, nil
}

// riskService classifies a sensitive exposed service by port. A port absent from
// this table is treated as inventory-only and produces no candidate (a clean
// host yields nothing — we never report a working control).
type riskService struct {
	severity string
	label    string
}

var riskByPort = map[int]riskService{
	21:    {db.SeverityHigh, "FTP (texto claro)"},
	23:    {db.SeverityHigh, "Telnet (texto claro)"},
	88:    {db.SeverityLow, "Kerberos (controlador de domínio)"},
	135:   {db.SeverityLow, "MSRPC"},
	139:   {db.SeverityMedium, "NetBIOS"},
	389:   {db.SeverityMedium, "LDAP"},
	445:   {db.SeverityMedium, "SMB"},
	636:   {db.SeverityMedium, "LDAPS"},
	1433:  {db.SeverityHigh, "Microsoft SQL Server"},
	1521:  {db.SeverityHigh, "Oracle DB"},
	3306:  {db.SeverityHigh, "MySQL"},
	3389:  {db.SeverityHigh, "RDP"},
	5432:  {db.SeverityHigh, "PostgreSQL"},
	5985:  {db.SeverityMedium, "WinRM (HTTP)"},
	5986:  {db.SeverityMedium, "WinRM (HTTPS)"},
	27017: {db.SeverityHigh, "MongoDB"},
}

// riskByService classifies a sensitive service by nmap's service name, so a
// service identified by -sV on a NON-STANDARD port is still flagged (avoiding
// false negatives when a DB/RDP listens off its default port).
var riskByService = map[string]riskService{
	"ms-sql-s":      {db.SeverityHigh, "Microsoft SQL Server"},
	"ms-wbt-server": {db.SeverityHigh, "RDP"},
	"microsoft-ds":  {db.SeverityMedium, "SMB"},
	"netbios-ssn":   {db.SeverityMedium, "NetBIOS"},
	"mysql":         {db.SeverityHigh, "MySQL"},
	"postgresql":    {db.SeverityHigh, "PostgreSQL"},
	"oracle-tns":    {db.SeverityHigh, "Oracle DB"},
	"mongodb":       {db.SeverityHigh, "MongoDB"},
	"ldap":          {db.SeverityMedium, "LDAP"},
	"wsman":         {db.SeverityMedium, "WinRM"},
	"ftp":           {db.SeverityHigh, "FTP (texto claro)"},
	"telnet":        {db.SeverityHigh, "Telnet (texto claro)"},
}

// ParseNmap turns nmap -oX XML into Candidates for sensitive exposed services.
func ParseNmap(raw []byte) ([]Candidate, error) {
	var run nmapRun
	if err := xml.Unmarshal(raw, &run); err != nil {
		return nil, fmt.Errorf("vacheck: XML do nmap invalido: %w", err)
	}
	var out []Candidate
	for _, h := range run.Hosts {
		ip := ""
		for _, a := range h.Addresses {
			if a.Type == "ipv4" || a.Type == "ipv6" {
				ip = a.Addr
			}
		}
		host := ""
		if len(h.Hostnames) > 0 {
			host = h.Hostnames[0].Name
		}
		for _, p := range h.Ports {
			if p.State.State != "open" {
				continue
			}
			risk, ok := riskByPort[p.PortID]
			if !ok {
				// porta não-padrão: tenta classificar pelo nome do serviço (-sV)
				risk, ok = riskByService[strings.ToLower(p.Service.Name)]
				if !ok {
					continue
				}
			}
			banner := strings.TrimSpace(p.Service.Product + " " + p.Service.Version)
			if banner == "" {
				banner = p.Service.Name
			}
			out = append(out, Candidate{
				Check:     "nmap.service",
				Title:     fmt.Sprintf("Serviço sensível exposto: %s (porta %d/%s)", risk.label, p.PortID, p.Protocol),
				VulnClass: "exposicao-de-servico",
				Severity:  risk.severity,
				Asset:     Asset{Host: host, IP: ip, Port: p.PortID, Proto: p.Protocol, Service: p.Service.Name, Product: p.Service.Product, Version: p.Service.Version, CPE: p.Service.CPE},
				Summary:   fmt.Sprintf("O serviço %s está acessível na rede em %s:%d. Serviços dessa natureza expostos ampliam a superfície de ataque e devem ter acesso restrito por segmentação/firewall.", risk.label, ipOr(ip, host), p.PortID),
				Evidence:  fmt.Sprintf("%d/%s %s -> %s", p.PortID, p.Protocol, p.Service.Name, banner),
				Tags:      []string{"foresea:rede"},
			})
		}
	}
	return out, nil
}

func ipOr(ip, host string) string {
	if ip != "" {
		return ip
	}
	return host
}
