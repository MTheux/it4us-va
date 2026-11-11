package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/MTheux/it4us-va/vacheck"
)

var cveIDPattern = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)
var numericVersionPattern = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*$`)
var nvdState = struct {
	sync.Mutex
	last  time.Time
	cache map[string]struct {
		data nvdResponse
		at   time.Time
	}
}{cache: make(map[string]struct {
	data nvdResponse
	at   time.Time
})}

type nvdMatch struct {
	Vulnerable     bool   `json:"vulnerable"`
	Criteria       string `json:"criteria"`
	StartIncluding string `json:"versionStartIncluding"`
	StartExcluding string `json:"versionStartExcluding"`
	EndIncluding   string `json:"versionEndIncluding"`
	EndExcluding   string `json:"versionEndExcluding"`
}
type nvdNode struct {
	Operator string     `json:"operator"`
	Negate   bool       `json:"negate"`
	CPES     []nvdMatch `json:"cpeMatch"`
	Children []nvdNode  `json:"children"`
}
type nvdCVE struct {
	ID           string `json:"id"`
	VulnStatus   string `json:"vulnStatus"`
	Published    string `json:"published"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Configurations []nvdConfiguration `json:"configurations"`
}
type nvdConfiguration struct {
	Operator string    `json:"operator"`
	Negate   bool      `json:"negate"`
	Nodes    []nvdNode `json:"nodes"`
}
type nvdVulnerability struct {
	CVE nvdCVE `json:"cve"`
}
type nvdResponse struct {
	TotalResults    int                `json:"totalResults"`
	Vulnerabilities []nvdVulnerability `json:"vulnerabilities"`
}

type vaCVEMatch struct {
	Target   string `json:"target"`
	Port     int    `json:"port"`
	Service  string `json:"service"`
	Version  string `json:"version,omitempty"`
	CPE      string `json:"cpe,omitempty"`
	Criteria string `json:"criteria,omitempty"`
	Status   string `json:"status"`
}
type vaCVEResult struct {
	CVE         string       `json:"cve"`
	CheckedAt   time.Time    `json:"checked_at"`
	Source      string       `json:"source"`
	Description string       `json:"description,omitempty"`
	Status      string       `json:"status"`
	Matches     []vaCVEMatch `json:"matches"`
	Note        string       `json:"note"`
	Automatic   bool         `json:"automatic,omitempty"`
}

func fetchNVD(r *http.Request, id string) (nvdResponse, error) {
	for {
		nvdState.Lock()
		if cached, ok := nvdState.cache[id]; ok && time.Since(cached.at) < time.Hour {
			nvdState.Unlock()
			return cached.data, nil
		}
		wait := time.Until(nvdState.last.Add(6 * time.Second))
		if wait <= 0 {
			nvdState.last = time.Now()
			nvdState.Unlock()
			break
		}
		nvdState.Unlock()
		timer := time.NewTimer(wait)
		select {
		case <-r.Context().Done():
			timer.Stop()
			return nvdResponse{}, r.Context().Err()
		case <-timer.C:
		}
	}
	url := "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + id
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, url, nil)
	if err != nil {
		return nvdResponse{}, err
	}
	req.Header.Set("User-Agent", "IT4US-VA/1.1 (CVE applicability review)")
	client := &http.Client{Timeout: 12 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nvdResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nvdResponse{}, fmt.Errorf("NVD returned HTTP %d", resp.StatusCode)
	}
	var data nvdResponse
	dec := json.NewDecoder(io.LimitReader(resp.Body, 4<<20))
	if err := dec.Decode(&data); err != nil {
		return nvdResponse{}, err
	}
	if len(data.Vulnerabilities) != 1 || data.Vulnerabilities[0].CVE.ID != id {
		return nvdResponse{}, errors.New("CVE not found in NVD")
	}
	nvdState.Lock()
	nvdState.cache[id] = struct {
		data nvdResponse
		at   time.Time
	}{data, time.Now()}
	nvdState.Unlock()
	return data, nil
}

func collectNVDCPE(nodes []nvdNode) []nvdMatch {
	var out []nvdMatch
	for _, node := range nodes {
		out = append(out, node.CPES...)
		out = append(out, collectNVDCPE(node.Children)...)
	}
	return out
}

func complexNVDCondition(nodes []nvdNode) bool {
	for _, node := range nodes {
		if node.Negate || strings.EqualFold(node.Operator, "AND") || complexNVDCondition(node.Children) {
			return true
		}
	}
	return false
}

func cpeParts(raw string) (part, vendor, product, version string, ok bool) {
	if strings.HasPrefix(raw, "cpe:2.3:") {
		p := strings.Split(raw, ":")
		if len(p) >= 6 {
			return p[2], p[3], p[4], p[5], true
		}
	}
	if strings.HasPrefix(raw, "cpe:/") {
		p := strings.Split(strings.TrimPrefix(raw, "cpe:/"), ":")
		if len(p) >= 3 {
			version = "*"
			if len(p) >= 4 {
				version = p[3]
			}
			return p[0], p[1], p[2], version, true
		}
	}
	return "", "", "", "", false
}

// compareNumericVersion is intentionally narrow. Vendor suffixes, distro
// backports and alphanumeric ranges remain inconclusive rather than guessed.
func compareNumericVersion(a, b string) (int, bool) {
	for _, v := range []string{a, b} {
		if !numericVersionPattern.MatchString(v) {
			return 0, false
		}
	}
	aa, bb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(aa) || i < len(bb); i++ {
		av, bv := 0, 0
		if i < len(aa) {
			av, _ = strconv.Atoi(aa[i])
		}
		if i < len(bb) {
			bv, _ = strconv.Atoi(bb[i])
		}
		if av < bv {
			return -1, true
		}
		if av > bv {
			return 1, true
		}
	}
	return 0, true
}

func cpeApplies(serviceCPE string, rule nvdMatch) (string, bool) {
	sp, sv, sprod, sver, sok := cpeParts(serviceCPE)
	rp, rv, rprod, rver, rok := cpeParts(rule.Criteria)
	if !sok || !rok || !strings.EqualFold(sp, rp) || !strings.EqualFold(sv, rv) || !strings.EqualFold(sprod, rprod) || !rule.Vulnerable {
		return "", false
	}
	if sver == "" || sver == "*" {
		return "inconclusive", true
	}
	if rver != "*" && rver != "-" && !strings.EqualFold(sver, rver) {
		return "", false
	}
	if rver != "*" && rver != "-" {
		return "possible", true
	}
	for _, bound := range []struct {
		v         string
		inclusive bool
		lower     bool
	}{{rule.StartIncluding, true, true}, {rule.StartExcluding, false, true}, {rule.EndIncluding, true, false}, {rule.EndExcluding, false, false}} {
		if bound.v == "" {
			continue
		}
		cmp, ok := compareNumericVersion(sver, bound.v)
		if !ok {
			return "inconclusive", true
		}
		if bound.lower && (cmp < 0 || (cmp == 0 && !bound.inclusive)) {
			return "", false
		}
		if !bound.lower && (cmp > 0 || (cmp == 0 && !bound.inclusive)) {
			return "", false
		}
	}
	return "possible", true
}

func assessCVE(id string, data nvdResponse, services []vacheck.Asset) vaCVEResult {
	result := vaCVEResult{CVE: id, CheckedAt: time.Now().UTC(), Source: "https://nvd.nist.gov/vuln/detail/" + id, Status: "not_detected", Matches: []vaCVEMatch{}, Note: "Correlação de CPE/versão observada; não confirma exploração, impacto nem ausência de patch/backport."}
	var cve *nvdCVE
	for i := range data.Vulnerabilities {
		if data.Vulnerabilities[i].CVE.ID == id {
			cve = &data.Vulnerabilities[i].CVE
			break
		}
	}
	if cve == nil {
		result.Status = "inconclusive"
		result.Note = "CVE não encontrada na resposta da NVD."
		return result
	}
	if strings.EqualFold(cve.VulnStatus, "Rejected") {
		result.Status = "inconclusive"
		result.Note = "Registro rejeitado pela NVD; não gera candidato de vulnerabilidade."
		return result
	}
	for _, d := range cve.Descriptions {
		if d.Lang == "en" {
			result.Description = d.Value
			break
		}
	}
	var rules []nvdMatch
	complex := false
	for _, config := range cve.Configurations {
		rules = append(rules, collectNVDCPE(config.Nodes)...)
		complex = complex || config.Negate || strings.EqualFold(config.Operator, "AND") || complexNVDCondition(config.Nodes)
	}
	if len(rules) == 0 {
		result.Status = "inconclusive"
		result.Note = "NVD não publicou critérios CPE para esta CVE."
		return result
	}
	for _, service := range services {
		best := vaCVEMatch{Target: service.IP, Port: service.Port, Service: service.Service, Version: service.Version, Status: "not_detected"}
		for _, serviceCPE := range service.CPE {
			for _, rule := range rules {
				status, matched := cpeApplies(serviceCPE, rule)
				if !matched {
					continue
				}
				best.CPE, best.Criteria, best.Status = serviceCPE, rule.Criteria, status
				if status == "possible" {
					break
				}
			}
			if best.Status == "possible" {
				break
			}
		}
		if len(service.CPE) == 0 {
			best.Status = "inconclusive"
		}
		if complex && best.Status == "possible" {
			best.Status = "inconclusive"
			result.Note = "A CVE exige condições CPE combinadas ou negadas; correspondência isolada não confirma aplicabilidade."
		}
		if best.Status == "possible" {
			result.Status = "possible"
		} else if best.Status == "inconclusive" && result.Status != "possible" {
			result.Status = "inconclusive"
		}
		result.Matches = append(result.Matches, best)
	}
	if len(services) == 0 {
		result.Status = "inconclusive"
		result.Note = "A campanha não contém serviços observados; execute discovery antes de correlacionar a CVE."
	}
	return result
}

func (s *Server) vaCheckCVE(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var body struct {
		RunID string `json:"run_id"`
		CVE   string `json:"cve"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, "invalid request")
		return
	}
	body.CVE = strings.ToUpper(strings.TrimSpace(body.CVE))
	if !validVARunID(body.RunID) || !cveIDPattern.MatchString(body.CVE) {
		writeErr(w, 400, "valid run ID and CVE ID required")
		return
	}
	record, err := s.vaReadRecord(body.RunID)
	if err != nil {
		writeErr(w, 404, "VA run not found")
		return
	}
	if record.Result == nil || (record.Status != "completed" && record.Status != "partial") {
		writeErr(w, 409, "complete discovery before CVE review")
		return
	}
	data, err := fetchNVD(r, body.CVE)
	if err != nil {
		writeErr(w, 503, "CVE source unavailable: "+err.Error())
		return
	}
	var services []vacheck.Asset
	for _, host := range record.Result.Hosts {
		if host.Status == "completed" {
			services = append(services, host.Services...)
			if len(host.Services) == 0 {
				for _, c := range host.Candidates {
					services = append(services, c.Asset)
				}
			}
		}
	}
	result := assessCVE(body.CVE, data, services)
	s.vaMu.Lock()
	defer s.vaMu.Unlock()
	current, err := s.vaReadRecord(body.RunID)
	if err != nil {
		writeErr(w, 500, "could not persist CVE review")
		return
	}
	filtered := make([]vaCVEResult, 0, len(current.CVEChecks)+1)
	for _, old := range current.CVEChecks {
		if old.CVE != body.CVE {
			filtered = append(filtered, old)
		}
	}
	current.CVEChecks = append(filtered, result)
	if err := s.vaWriteRecord(current); err != nil {
		writeErr(w, 500, "could not persist CVE review")
		return
	}
	writeJSON(w, 200, result)
}
