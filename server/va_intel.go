package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const epssURL = "https://api.first.org/data/v1/epss"
const kevURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
const ghsaURL = "https://api.github.com/advisories"

type vaIntelReference struct {
	URL    string `json:"url"`
	Source string `json:"source,omitempty"`
}

type vaCVEIntel struct {
	CVE               string             `json:"cve"`
	Description       string             `json:"description,omitempty"`
	Published         string             `json:"published,omitempty"`
	VulnStatus        string             `json:"vuln_status,omitempty"`
	NVDURL            string             `json:"nvd_url"`
	ExploitReferences []vaIntelReference `json:"exploit_references"`
	References        []vaIntelReference `json:"references"`
	Advisories        []vaIntelReference `json:"advisories"`
	EPSS              *float64           `json:"epss,omitempty"`
	EPSSPercentile    *float64           `json:"epss_percentile,omitempty"`
	KEV               bool               `json:"kev"`
	KEVDate           string             `json:"kev_date,omitempty"`
	SourceStatus      map[string]string  `json:"source_status"`
}

var kevCache = struct {
	sync.Mutex
	at   time.Time
	data map[string]string
}{}

func safeIntelURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Hostname() != "" && u.User == nil
}

func nvdIntel(cve nvdCVE) vaCVEIntel {
	out := vaCVEIntel{
		CVE: cve.ID, Published: cve.Published, VulnStatus: cve.VulnStatus, NVDURL: "https://nvd.nist.gov/vuln/detail/" + cve.ID,
		ExploitReferences: []vaIntelReference{}, References: []vaIntelReference{}, Advisories: []vaIntelReference{},
		SourceStatus: map[string]string{"nvd": "ok", "epss": "unavailable", "kev": "unavailable", "github": "unavailable"},
	}
	for _, d := range cve.Descriptions {
		if d.Lang == "pt" || (out.Description == "" && d.Lang == "en") {
			out.Description = d.Value
		}
	}
	seen := map[string]bool{}
	for _, ref := range cve.References {
		if !safeIntelURL(ref.URL) || seen[ref.URL] {
			continue
		}
		seen[ref.URL] = true
		item := vaIntelReference{URL: ref.URL, Source: ref.Source}
		isExploit := false
		for _, tag := range ref.Tags {
			if strings.EqualFold(tag, "Exploit") {
				isExploit = true
				break
			}
		}
		if isExploit && len(out.ExploitReferences) < 8 {
			out.ExploitReferences = append(out.ExploitReferences, item)
		} else if !isExploit && len(out.References) < 16 {
			out.References = append(out.References, item)
		}
	}
	return out
}

func getBoundedJSON(ctx context.Context, client *http.Client, endpoint string, maxBytes int64, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "IT4US-VA/1.4 (defensive CVE lookup)")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("source returned HTTP %d", resp.StatusCode)
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, maxBytes+1))
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return fmt.Errorf("source returned trailing or oversized JSON")
	}
	return nil
}

func lookupEPSS(ctx context.Context, client *http.Client, id string) (*float64, *float64, error) {
	return lookupEPSSFrom(ctx, client, epssURL, id)
}

func lookupEPSSFrom(ctx context.Context, client *http.Client, endpoint, id string) (*float64, *float64, error) {
	uri := endpoint + "?cve=" + url.QueryEscape(id)
	var response struct {
		Data []struct {
			CVE        string `json:"cve"`
			EPSS       string `json:"epss"`
			Percentile string `json:"percentile"`
		} `json:"data"`
	}
	if err := getBoundedJSON(ctx, client, uri, 128<<10, &response); err != nil {
		return nil, nil, err
	}
	for _, item := range response.Data {
		if item.CVE != id {
			continue
		}
		score, e1 := strconv.ParseFloat(item.EPSS, 64)
		percentile, e2 := strconv.ParseFloat(item.Percentile, 64)
		if e1 != nil || e2 != nil || score < 0 || score > 1 || percentile < 0 || percentile > 1 {
			return nil, nil, fmt.Errorf("invalid EPSS data")
		}
		return &score, &percentile, nil
	}
	return nil, nil, nil
}

func lookupKEV(ctx context.Context, client *http.Client, id string) (string, bool, error) {
	kevCache.Lock()
	if kevCache.data != nil && time.Since(kevCache.at) < 6*time.Hour {
		date, ok := kevCache.data[id]
		kevCache.Unlock()
		return date, ok, nil
	}
	kevCache.Unlock()
	var response struct {
		Vulnerabilities []struct {
			CVEID     string `json:"cveID"`
			DateAdded string `json:"dateAdded"`
		} `json:"vulnerabilities"`
	}
	if err := getBoundedJSON(ctx, client, kevURL, 8<<20, &response); err != nil {
		return "", false, err
	}
	data := make(map[string]string, len(response.Vulnerabilities))
	for _, item := range response.Vulnerabilities {
		if cveIDPattern.MatchString(item.CVEID) {
			data[item.CVEID] = item.DateAdded
		}
	}
	kevCache.Lock()
	kevCache.data, kevCache.at = data, time.Now()
	kevCache.Unlock()
	date, ok := data[id]
	return date, ok, nil
}

func lookupGHSAFrom(ctx context.Context, client *http.Client, endpoint, id string) ([]vaIntelReference, error) {
	uri := endpoint + "?cve_id=" + url.QueryEscape(id) + "&per_page=5"
	var data []struct {
		CVEID   string `json:"cve_id"`
		GHSAID  string `json:"ghsa_id"`
		HTMLURL string `json:"html_url"`
	}
	if err := getBoundedJSON(ctx, client, uri, 512<<10, &data); err != nil {
		return nil, err
	}
	out := []vaIntelReference{}
	for _, item := range data {
		if item.CVEID == id && safeIntelURL(item.HTMLURL) {
			out = append(out, vaIntelReference{URL: item.HTMLURL, Source: item.GHSAID})
		}
	}
	return out, nil
}

func (s *Server) vaLookupCVE(w http.ResponseWriter, r *http.Request) {
	id := strings.ToUpper(strings.TrimSpace(r.PathValue("id")))
	if !cveIDPattern.MatchString(id) {
		writeErr(w, http.StatusBadRequest, "valid CVE ID required")
		return
	}
	data, err := fetchNVD(r, id)
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, "NVD lookup unavailable: "+err.Error())
		return
	}
	result := nvdIntel(data.Vulnerabilities[0].CVE)
	client := &http.Client{Timeout: 10 * time.Second}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	type epssResult struct {
		score, percentile *float64
		err               error
	}
	type kevResult struct {
		date  string
		found bool
		err   error
	}
	type ghsaResult struct {
		items []vaIntelReference
		err   error
	}
	epssDone, kevDone, ghsaDone := make(chan epssResult, 1), make(chan kevResult, 1), make(chan ghsaResult, 1)
	go func() {
		score, percentile, err := lookupEPSS(ctx, client, id)
		epssDone <- epssResult{score, percentile, err}
	}()
	go func() {
		date, found, err := lookupKEV(ctx, client, id)
		kevDone <- kevResult{date, found, err}
	}()
	go func() {
		items, err := lookupGHSAFrom(ctx, client, ghsaURL, id)
		ghsaDone <- ghsaResult{items, err}
	}()
	epss := <-epssDone
	kev := <-kevDone
	ghsa := <-ghsaDone
	if epss.err == nil {
		result.EPSS, result.EPSSPercentile = epss.score, epss.percentile
		result.SourceStatus["epss"] = "ok"
	}
	if kev.err == nil {
		result.KEV, result.KEVDate = kev.found, kev.date
		result.SourceStatus["kev"] = "ok"
	}
	if ghsa.err == nil {
		result.Advisories = ghsa.items
		result.SourceStatus["github"] = "ok"
	}
	writeJSON(w, http.StatusOK, result)
}
