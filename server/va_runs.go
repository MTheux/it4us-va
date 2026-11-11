package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/MTheux/it4us-va/db"
	"github.com/MTheux/it4us-va/vascan"
)

// A VA run is separate from the conversational task engine. The scanner only
// receives the reviewed IP/CIDR expansion and fixed Nmap service checks.
type vaRunRecord struct {
	ID             string            `json:"id"`
	Campaign       vascan.Campaign   `json:"campaign"`
	Status         string            `json:"status"`
	Phase          string            `json:"phase,omitempty"`
	CreatedAt      time.Time         `json:"created_at"`
	FinishedAt     *time.Time        `json:"finished_at,omitempty"`
	TotalHosts     int               `json:"total_hosts"`
	CompletedHosts int               `json:"completed_hosts"`
	FailedHosts    int               `json:"failed_hosts"`
	CandidateCount int               `json:"candidate_count"`
	Error          string            `json:"error,omitempty"`
	Result         *vascan.Result    `json:"result,omitempty"`
	CVEChecks      []vaCVEResult     `json:"cve_checks,omitempty"`
	CVEAuto        *vaAutoCVESummary `json:"cve_auto,omitempty"`
}

type vaActiveRun struct {
	cancel         context.CancelFunc
	completedHosts int
	failedHosts    int
}

// vaScopedScanner rechecks the task gate immediately before each host and deep
// check. Disabling an allow rule or adding a block rule during a campaign stops
// subsequent target traffic without relying on a stale plan-time snapshot.
type vaScopedScanner struct {
	pg      *db.DB
	taskID  int64
	scanner vascan.NmapScanner
}

func (v vaScopedScanner) allowed(target string) error {
	global, err := v.pg.ListAssetInterceptRules()
	if err != nil {
		return err
	}
	block, allow, err := v.pg.Assets().TaskVAAllowRules(v.taskID)
	if err != nil {
		return err
	}
	return db.ValidateTaskIPScope([]string{target}, append(global, block...), allow)
}

func (v vaScopedScanner) Scan(ctx context.Context, target string, ports []int) ([]byte, error) {
	if err := v.allowed(target); err != nil {
		return nil, fmt.Errorf("VA scope revoked before host %s: %w", target, err)
	}
	return v.scanner.Scan(ctx, target, ports)
}

func (v vaScopedScanner) ScanDeep(ctx context.Context, target string, ports []int) ([]byte, error) {
	if err := v.allowed(target); err != nil {
		return nil, fmt.Errorf("VA scope revoked before deep check %s: %w", target, err)
	}
	return v.scanner.ScanDeep(ctx, target, ports)
}

func (s *Server) vaCapabilities(w http.ResponseWriter, _ *http.Request) {
	_, err := exec.LookPath("nmap")
	writeJSON(w, http.StatusOK, map[string]any{
		"scanner_available": err == nil,
		"scanner":           "Nmap TCP connect / service detection",
		"llm_required":      false,
		"mcp_required":      false,
	})
}

func (s *Server) vaPlan(w http.ResponseWriter, r *http.Request) {
	campaign, targets, ok := s.vaReadCampaign(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"campaign":     campaign.Name,
		"task_id":      campaign.TaskID,
		"targets":      targets,
		"ports":        campaign.Ports,
		"port_count":   campaign.PortCount(),
		"port_profile": campaign.PortProfile,
		"depth":        campaign.Depth,
		"expires_at":   campaign.ExpiresAt,
	})
}

func (s *Server) vaReadCampaign(w http.ResponseWriter, r *http.Request) (vascan.Campaign, []string, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var campaign vascan.Campaign
	if err := dec.Decode(&campaign); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid campaign JSON: "+err.Error())
		return campaign, nil, false
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		writeErr(w, http.StatusBadRequest, "campaign contains trailing data")
		return campaign, nil, false
	}
	if err := campaign.Validate(time.Now()); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return campaign, nil, false
	}
	if s.m.PG() == nil {
		writeErr(w, http.StatusServiceUnavailable, "PostgreSQL unavailable")
		return campaign, nil, false
	}
	task, err := s.m.PG().GetTask(campaign.TaskID)
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, "could not verify task")
		return campaign, nil, false
	}
	if task == nil {
		writeErr(w, http.StatusBadRequest, "task does not exist")
		return campaign, nil, false
	}
	targets, _ := campaign.ExpandedTargets()
	globalBlock, err := s.m.PG().ListAssetInterceptRules()
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, "could not verify global asset rules")
		return campaign, nil, false
	}
	taskBlock, taskAllow, err := s.m.PG().Assets().TaskVAAllowRules(campaign.TaskID)
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, "could not verify task asset rules")
		return campaign, nil, false
	}
	if err := db.ValidateTaskIPScope(targets, append(globalBlock, taskBlock...), taskAllow); err != nil {
		writeErr(w, http.StatusForbidden, err.Error())
		return campaign, nil, false
	}
	return campaign, targets, true
}

func (s *Server) vaStartRun(w http.ResponseWriter, r *http.Request) {
	campaign, targets, ok := s.vaReadCampaign(w, r)
	if !ok {
		return
	}
	if _, err := exec.LookPath("nmap"); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "Nmap is not installed on the VA worker")
		return
	}
	seed := make([]byte, 12)
	if _, err := rand.Read(seed); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not create run ID")
		return
	}
	id := hex.EncodeToString(seed)
	ctx, cancel := context.WithCancel(s.ctx)
	record := vaRunRecord{ID: id, Campaign: campaign, Status: "running", CreatedAt: time.Now().UTC(), TotalHosts: len(targets)}
	s.vaMu.Lock()
	if len(s.vaActive) >= 1 {
		s.vaMu.Unlock()
		cancel()
		writeErr(w, http.StatusConflict, "a VA campaign is already running on this worker")
		return
	}
	if err := s.vaWriteRecord(record); err != nil {
		s.vaMu.Unlock()
		cancel()
		writeErr(w, http.StatusInternalServerError, "could not save campaign receipt")
		return
	}
	s.vaActive[id] = &vaActiveRun{cancel: cancel}
	s.vaMu.Unlock()
	go s.vaExecute(ctx, record)
	writeJSON(w, http.StatusAccepted, record)
}

func (s *Server) vaExecute(ctx context.Context, record vaRunRecord) {
	defer func() {
		s.vaMu.Lock()
		delete(s.vaActive, record.ID)
		s.vaMu.Unlock()
	}()
	result, runErr := vascan.RunWithProgress(ctx, record.Campaign, vaScopedScanner{pg: s.m.PG(), taskID: record.Campaign.TaskID}, time.Now, func(host vascan.HostResult) {
		s.vaMu.Lock()
		if active := s.vaActive[record.ID]; active != nil {
			if host.Status == "completed" {
				active.completedHosts++
			} else {
				active.failedHosts++
			}
		}
		s.vaMu.Unlock()
	})
	completed, failed := 0, 0
	deepFailures := 0
	for _, host := range result.Hosts {
		if host.Status == "completed" {
			completed++
			if host.DeepError != "" {
				deepFailures++
			}
		} else {
			failed++
		}
	}
	record.CompletedHosts, record.FailedHosts = completed, failed
	record.Result = &result
	if len(result.Hosts) > 0 {
		count, err := vascan.Persist(s.m.PG(), record.Campaign.TaskID, result)
		record.CandidateCount = count
		if err != nil {
			record.Error = "candidate persistence failed: " + err.Error()
		}
	}
	switch {
	case errors.Is(runErr, context.Canceled):
		record.Status = "canceled"
	case runErr != nil || record.Error != "":
		record.Status = "failed"
	case failed > 0 || deepFailures > 0:
		record.Status = "partial"
	default:
		record.Status = "completed"
	}
	if runErr != nil && record.Error == "" {
		record.Error = runErr.Error()
	}
	if record.Status == "completed" || record.Status == "partial" {
		finalStatus := record.Status
		record.Status, record.Phase = "running", "cve_review"
		_ = s.vaWriteRecord(record)
		s.vaAutoReview(ctx, &record)
		if record.CVEAuto != nil {
			record.CandidateCount += record.CVEAuto.Candidates
		}
		record.Status, record.Phase = finalStatus, ""
	}
	finished := time.Now().UTC()
	record.FinishedAt = &finished
	if err := s.vaWriteRecord(record); err != nil {
		// The in-memory run has ended; an initial receipt remains on disk and is
		// reported as interrupted after restart, never as a successful scan.
		fmt.Fprintf(os.Stderr, "[va] save run %s: %v\n", record.ID, err)
	}
}

func (s *Server) vaListRuns(w http.ResponseWriter, _ *http.Request) {
	dir := filepath.Join(s.m.dir, "va-runs")
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		writeJSON(w, http.StatusOK, map[string]any{"runs": []vaRunRecord{}})
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not list VA runs")
		return
	}
	runs := make([]vaRunRecord, 0)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "campaign-") || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(strings.TrimPrefix(entry.Name(), "campaign-"), ".json")
		if !validVARunID(id) {
			continue
		}
		record, err := s.vaReadRecord(id)
		if err != nil {
			continue
		}
		s.vaCurrent(&record)
		record.Result = nil
		runs = append(runs, record)
	}
	sort.Slice(runs, func(i, j int) bool { return runs[i].CreatedAt.After(runs[j].CreatedAt) })
	if len(runs) > 50 {
		runs = runs[:50]
	}
	writeJSON(w, http.StatusOK, map[string]any{"runs": runs})
}

func (s *Server) vaGetRun(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validVARunID(id) {
		writeErr(w, http.StatusBadRequest, "invalid run ID")
		return
	}
	record, err := s.vaReadRecord(id)
	if errors.Is(err, os.ErrNotExist) {
		writeErr(w, http.StatusNotFound, "VA run not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not read VA run")
		return
	}
	s.vaCurrent(&record)
	writeJSON(w, http.StatusOK, record)
}

func (s *Server) vaCancelRun(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validVARunID(id) {
		writeErr(w, http.StatusBadRequest, "invalid run ID")
		return
	}
	s.vaMu.Lock()
	active := s.vaActive[id]
	s.vaMu.Unlock()
	if active == nil {
		writeErr(w, http.StatusConflict, "VA run is not active")
		return
	}
	active.cancel()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) vaCurrent(record *vaRunRecord) {
	if record.Status != "running" {
		return
	}
	s.vaMu.Lock()
	active := s.vaActive[record.ID]
	if active != nil {
		record.CompletedHosts = active.completedHosts
		record.FailedHosts = active.failedHosts
	} else {
		record.Status = "interrupted"
	}
	s.vaMu.Unlock()
}

func validVARunID(id string) bool {
	if len(id) != 24 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

func (s *Server) vaReadRecord(id string) (vaRunRecord, error) {
	path := filepath.Join(s.m.dir, "va-runs", "campaign-"+id+".json")
	f, err := os.Open(path)
	if err != nil {
		return vaRunRecord{}, err
	}
	defer f.Close()
	var record vaRunRecord
	err = json.NewDecoder(f).Decode(&record)
	return record, err
}

func (s *Server) vaWriteRecord(record vaRunRecord) error {
	dir := filepath.Join(s.m.dir, "va-runs")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".campaign-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if err := json.NewEncoder(f).Encode(record); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), filepath.Join(dir, "campaign-"+record.ID+".json"))
}
