package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/MTheux/it4us-va/db"
	"github.com/MTheux/it4us-va/vacheck"
	"github.com/MTheux/it4us-va/vascan"
)

const maxAutoCPE = 8
const maxAutoCVEs = 40
const maxAutoMatches = 200
const maxNVDPage = 200

type vaAutoCVESummary struct {
	Status       string `json:"status"` // completed, partial, skipped, unavailable
	CPEsChecked  int    `json:"cpes_checked"`
	CVEsChecked  int    `json:"cves_checked"`
	Candidates   int    `json:"candidates"`
	CoverageNote string `json:"coverage_note,omitempty"`
}

// nvdCPEName only accepts an observed CPE with a concrete version. Guessing a
// product from a generic banner would flood the SOC with false CVE matches.
func nvdCPEName(raw string) (string, bool) {
	if strings.HasPrefix(raw, "cpe:2.3:") {
		parts := strings.Split(raw, ":")
		if len(parts) == 13 && concreteCPEVersion(parts[5]) {
			return raw, true
		}
		return "", false
	}
	if !strings.HasPrefix(raw, "cpe:/") {
		return "", false
	}
	parts := strings.Split(strings.TrimPrefix(raw, "cpe:/"), ":")
	if len(parts) < 4 || len(parts) > 5 || !concreteCPEVersion(parts[3]) {
		return "", false
	}
	out := []string{"cpe", "2.3", parts[0], parts[1], parts[2], parts[3]}
	if len(parts) == 5 {
		out = append(out, parts[4])
	} else {
		out = append(out, "*")
	}
	for len(out) < 13 {
		out = append(out, "*")
	}
	return strings.Join(out, ":"), true
}

func concreteCPEVersion(version string) bool {
	return version != "" && version != "*" && version != "-" && !strings.ContainsAny(version, "\\ ")
}

// The public NVD service expects pacing; this clock is shared with the manual
// CVE lookup so simultaneous SOC and automatic requests stay bounded.
func waitNVD(ctx context.Context) error {
	for {
		nvdState.Lock()
		wait := time.Until(nvdState.last.Add(6 * time.Second))
		if wait <= 0 {
			nvdState.last = time.Now()
			nvdState.Unlock()
			return nil
		}
		nvdState.Unlock()
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func fetchNVDByCPE(ctx context.Context, endpoint string, client *http.Client, cpe string) (nvdResponse, error) {
	if err := waitNVD(ctx); err != nil {
		return nvdResponse{}, err
	}
	uri, err := url.Parse(endpoint)
	if err != nil {
		return nvdResponse{}, err
	}
	query := uri.Query()
	query.Set("cpeName", cpe)
	query.Set("resultsPerPage", strconv.Itoa(maxNVDPage))
	uri.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri.String(), nil)
	if err != nil {
		return nvdResponse{}, err
	}
	req.Header.Set("User-Agent", "IT4US-VA/1.2 (bounded CVE applicability review)")
	resp, err := client.Do(req)
	if err != nil {
		return nvdResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nvdResponse{}, fmt.Errorf("NVD returned HTTP %d", resp.StatusCode)
	}
	var data nvdResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&data); err != nil {
		return nvdResponse{}, err
	}
	return data, nil
}

func autoCVEServices(result vascan.Result) map[string][]vacheck.Asset {
	byCPE := make(map[string][]vacheck.Asset)
	for _, host := range result.Hosts {
		if host.Status != "completed" {
			continue
		}
		for _, service := range host.Services {
			if net.ParseIP(service.IP) == nil || !net.ParseIP(service.IP).Equal(net.ParseIP(host.Target)) || service.Port < 1 || service.Port > 65535 {
				continue
			}
			for _, raw := range service.CPE {
				if cpe, ok := nvdCPEName(raw); ok {
					byCPE[cpe] = append(byCPE[cpe], service)
				}
			}
		}
	}
	return byCPE
}

// vaAutoReview performs source-only CVE research after the scoped scan. It
// never sends another request to the customer target or confirms a finding.
// A partial NVD response is explicit in the receipt instead of being shown as
// a clean bill of health.
func (s *Server) vaAutoReview(ctx context.Context, record *vaRunRecord) {
	s.vaAutoReviewFrom(ctx, record, "https://services.nvd.nist.gov/rest/json/cves/2.0", &http.Client{Timeout: 12 * time.Second})
}

func (s *Server) vaAutoReviewFrom(ctx context.Context, record *vaRunRecord, endpoint string, client *http.Client) {
	summary := &vaAutoCVESummary{Status: "skipped"}
	record.CVEAuto = summary
	if record.Result == nil || s.m.PG() == nil {
		summary.CoverageNote = "Sem resultado de discovery ou banco de dados."
		return
	}
	byCPE := autoCVEServices(*record.Result)
	if len(byCPE) == 0 {
		summary.CoverageNote = "Nenhum CPE com versão exata foi observado; não há base para buscar CVEs automaticamente."
		return
	}
	keys := make([]string, 0, len(byCPE))
	for cpe := range byCPE {
		keys = append(keys, cpe)
	}
	sort.Strings(keys)
	truncated := len(keys) > maxAutoCPE
	if truncated {
		keys = keys[:maxAutoCPE]
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	found := make(map[string]nvdResponse)
	assets := make(map[string][]vacheck.Asset)
	seenAssets := make(map[string]map[string]bool)
	var sourceErr error
	for _, cpe := range keys {
		data, err := fetchNVDByCPE(ctx, endpoint, client, cpe)
		if err != nil {
			sourceErr = err
			break
		}
		summary.CPEsChecked++
		if data.TotalResults > len(data.Vulnerabilities) {
			truncated = true
		}
		// NVD returns older publications first. Review the newest records within
		// the bounded page so the cap does not silently favor old CVEs.
		sort.Slice(data.Vulnerabilities, func(i, j int) bool {
			return data.Vulnerabilities[i].CVE.Published > data.Vulnerabilities[j].CVE.Published
		})
		for _, item := range data.Vulnerabilities {
			id := item.CVE.ID
			if !cveIDPattern.MatchString(id) {
				continue
			}
			if _, exists := found[id]; !exists && len(found) >= maxAutoCVEs {
				truncated = true
				continue
			}
			if _, exists := found[id]; !exists {
				found[id] = nvdResponse{Vulnerabilities: []nvdVulnerability{item}}
			}
			if seenAssets[id] == nil {
				seenAssets[id] = make(map[string]bool)
			}
			for _, asset := range byCPE[cpe] {
				key := asset.IP + ":" + strconv.Itoa(asset.Port) + "/" + asset.Service
				if !seenAssets[id][key] {
					seenAssets[id][key] = true
					assets[id] = append(assets[id], asset)
				}
			}
		}
	}
	ids := make([]string, 0, len(found))
	for id := range found {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	totalMatches := 0
	persistFailed := false
	for _, id := range ids {
		remaining := maxAutoMatches - totalMatches
		if remaining <= 0 {
			truncated = true
			break
		}
		if len(assets[id]) > remaining {
			assets[id] = assets[id][:remaining]
			truncated = true
		}
		check := assessCVE(id, found[id], assets[id])
		totalMatches += len(check.Matches)
		check.Automatic = true
		if check.Status == "not_detected" {
			check.Status = "inconclusive"
			check.Note = "A busca da NVD retornou a CVE para o CPE, mas os critérios publicados não puderam ser reconciliados com a versão observada."
		}
		record.CVEChecks = append(record.CVEChecks, check)
		summary.CVEsChecked++
		if check.Status != "possible" {
			continue
		}
		for _, match := range check.Matches {
			if match.Status != "possible" {
				continue
			}
			if err := s.persistAutoCVECandidate(record.Campaign.TaskID, check, match); err != nil {
				sourceErr = err
				persistFailed = true
				break
			}
			summary.Candidates++
		}
		if sourceErr != nil {
			break
		}
	}
	switch {
	case persistFailed:
		summary.Status = "partial"
		summary.CoverageNote = "Falha ao gravar candidatos; revisão automática incompleta."
	case summary.CPEsChecked == 0 && sourceErr != nil:
		summary.Status = "unavailable"
		summary.CoverageNote = "Fonte NVD indisponível; discovery preservado, correlação automática não concluída."
	case sourceErr != nil || truncated:
		summary.Status = "partial"
		summary.CoverageNote = "Correlação incompleta por limite de consultas, volume de CVEs ou indisponibilidade da NVD."
	default:
		summary.Status = "completed"
		summary.CoverageNote = "CPEs observados consultados na NVD; correspondências exigem validação específica pelo SOC."
	}
	if errors.Is(sourceErr, context.Canceled) {
		summary.CoverageNote = "Correlação cancelada; resultados parciais preservados."
	}
}

func (s *Server) persistAutoCVECandidate(taskID int64, check vaCVEResult, match vaCVEMatch) error {
	pg := s.m.PG()
	ipID, err := pg.Assets().UpsertIP(db.UpsertIPReq{IP: match.Target, TaskID: taskID})
	if err != nil {
		return err
	}
	assetIDs := []int64{ipID}
	if match.Service != "" {
		serviceID, err := pg.Assets().UpsertOtherService(db.UpsertOtherServiceReq{IP: match.Target, Port: match.Port, ServiceName: match.Service, TaskID: taskID})
		if err != nil {
			return err
		}
		assetIDs = append(assetIDs, serviceID)
	}
	title := fmt.Sprintf("%s · %s:%d/tcp", check.CVE, match.Target, match.Port)
	summary := "Correspondência automática entre CPE/versão observados e critérios publicados pela NVD. Pendente de verificação específica da CVE e revisão de patch/backport."
	evidence := fmt.Sprintf("CVE: %s\nCPE observado: %s\nCritério NVD: %s\nVersão observada: %s\nFonte: %s", check.CVE, match.CPE, match.Criteria, match.Version, check.Source)
	_, _, err = pg.AddVACVECandidate(taskID, ipID, "cve-possivel", title, db.SeverityMedium, summary, evidence, assetIDs)
	return err
}
