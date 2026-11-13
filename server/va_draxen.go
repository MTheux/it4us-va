package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type boundedDraxenOutput struct {
	buf   bytes.Buffer
	limit int
	full  bool
}

func (w *boundedDraxenOutput) Write(p []byte) (int, error) {
	if w.buf.Len()+len(p) > w.limit {
		w.full = true
		return 0, io.ErrShortWrite
	}
	return w.buf.Write(p)
}

type vaDraxenReview struct {
	Status       string `json:"status"`
	Offline      bool   `json:"offline"`
	Artifacts    int    `json:"artifacts"`
	Proposals    int    `json:"proposals"`
	NetworkCalls int    `json:"network_calls"`
	Note         string `json:"note,omitempty"`
}

// Draxen's Hermes infrastructure inspector runs only against a local receipt.
// The bridge is deliberately separate from active scanning and has no network
// target argument. Its own audit files stay under this VA run's artifact root.
func (s *Server) vaReviewWithDraxen(ctx context.Context, record *vaRunRecord) {
	python := strings.TrimSpace(os.Getenv("IT4US_DRAXEN_PYTHON"))
	bridge := strings.TrimSpace(os.Getenv("IT4US_DRAXEN_BRIDGE"))
	engine := strings.TrimSpace(os.Getenv("IT4US_DRAXEN_ENGINE_DIR"))
	if python == "" || bridge == "" || engine == "" {
		record.Draxen = &vaDraxenReview{Status: "unavailable", Note: "Runtime Draxen não configurado"}
		s.vaAppendEvent(record.ID, vaEvent{Stage: "draxen", Status: "unavailable", Detail: "Runtime de revisão offline não configurado"})
		return
	}
	for _, path := range []string{python, bridge, filepath.Join(engine, "hermes_driver.py")} {
		if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
			record.Draxen = &vaDraxenReview{Status: "unavailable", Note: "Arquivo do runtime Draxen indisponível"}
			s.vaAppendEvent(record.ID, vaEvent{Stage: "draxen", Status: "unavailable", Detail: "Arquivo do runtime de revisão indisponível"})
			return
		}
	}
	input, err := json.MarshalIndent(map[string]any{
		"run_id": record.ID, "task_id": record.Campaign.TaskID,
		"campaign": record.Campaign, "result": record.Result,
		"cve_checks": record.CVEChecks, "cve_auto": record.CVEAuto,
	}, "", "  ")
	if err == nil {
		err = s.vaSaveArtifact(record.ID, "analysis-input.json", input)
	}
	if err != nil {
		record.Draxen = &vaDraxenReview{Status: "failed", Note: "Não foi possível preparar o recibo para revisão"}
		s.vaAppendEvent(record.ID, vaEvent{Stage: "draxen", Status: "failed", Detail: "Recibo de análise indisponível"})
		return
	}
	s.vaAppendEvent(record.ID, vaEvent{Stage: "draxen", Status: "started", Detail: "Revisão offline de infraestrutura iniciada"})
	reviewCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(reviewCtx, python, bridge, s.vaArtifactDir(record.ID), filepath.Join(s.vaArtifactDir(record.ID), "analysis-input.json"), "it4us-va-"+record.ID)
	cmd.Env = append(os.Environ(), "IT4US_DRAXEN_ENGINE_DIR="+engine)
	stdout := boundedDraxenOutput{limit: 4 << 20}
	stderr := boundedDraxenOutput{limit: 4096}
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	if stdout.full || stderr.full {
		err = errors.New("Draxen output exceeded limit")
	}
	if err != nil {
		record.Draxen = &vaDraxenReview{Status: "failed", Note: "Revisão offline falhou; consulte o log do worker"}
		s.vaAppendEvent(record.ID, vaEvent{Stage: "draxen", Status: "failed", Detail: "Revisão offline falhou"})
		fmt.Fprintf(os.Stderr, "[va] draxen review %s: %v\n", record.ID, err)
		return
	}
	var result struct {
		OK                bool `json:"ok"`
		Offline           bool `json:"offline"`
		NetworkRequests   int  `json:"network_requests"`
		ExecutedArtifacts int  `json:"executed_artifacts"`
		ArtifactAnalysis  struct {
			Artifacts []json.RawMessage `json:"artifacts"`
		} `json:"artifact_analysis"`
		VAReview struct {
			Hosts []struct {
				Target          string            `json:"target"`
				ProposedActions []json.RawMessage `json:"proposed_actions"`
			} `json:"hosts"`
			ExecutedActions int `json:"executed_actions"`
		} `json:"va_review"`
		Handoff struct {
			Dir string `json:"dir"`
		} `json:"handoff"`
	}
	if err := json.Unmarshal(stdout.buf.Bytes(), &result); err != nil || !result.OK || !result.Offline || result.NetworkRequests != 0 || result.ExecutedArtifacts != 0 || result.VAReview.ExecutedActions != 0 {
		record.Draxen = &vaDraxenReview{Status: "failed", Note: "Contrato de revisão offline inválido"}
		s.vaAppendEvent(record.ID, vaEvent{Stage: "draxen", Status: "failed", Detail: "Contrato de revisão offline inválido"})
		return
	}
	if err := s.vaSaveArtifact(record.ID, "draxen/analysis.json", stdout.buf.Bytes()); err != nil {
		record.Draxen = &vaDraxenReview{Status: "failed", Note: "Análise concluída, mas o artefato não foi preservado"}
		s.vaAppendEvent(record.ID, vaEvent{Stage: "draxen", Status: "failed", Detail: "Artefato de análise não foi preservado"})
		return
	}
	if body, err := json.MarshalIndent(result.VAReview, "", "  "); err == nil {
		_ = s.vaSaveArtifact(record.ID, "draxen/va-plan.json", body)
	}
	handoffRoot := filepath.Join(s.vaArtifactDir(record.ID), "report-corpus", "engagements", "it4us-va-"+record.ID, "handoffs")
	rel, err := filepath.Rel(handoffRoot, result.Handoff.Dir)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		record.Draxen = &vaDraxenReview{Status: "failed", Note: "Handoff fora do diretório da execução"}
		s.vaAppendEvent(record.ID, vaEvent{Stage: "draxen", Status: "failed", Detail: "Handoff fora do diretório da execução"})
		return
	}
	for _, name := range []string{"HANDOFF.md", "manifest.json", "agent-state.json", "findings.json", "audit.jsonl", "coverage-diff.json", "capability-plan.json"} {
		path := filepath.Join(result.Handoff.Dir, name)
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() > 8<<20 {
			record.Draxen = &vaDraxenReview{Status: "failed", Note: "Arquivo do handoff indisponível"}
			s.vaAppendEvent(record.ID, vaEvent{Stage: "draxen", Status: "failed", Detail: "Arquivo do handoff indisponível"})
			return
		}
		body, err := os.ReadFile(path)
		if err == nil {
			err = s.vaSaveArtifact(record.ID, "draxen/"+name, body)
		}
		if err != nil {
			record.Draxen = &vaDraxenReview{Status: "failed", Note: "Falha ao preservar o handoff"}
			s.vaAppendEvent(record.ID, vaEvent{Stage: "draxen", Status: "failed", Detail: "Falha ao preservar o handoff"})
			return
		}
	}
	var proposals int
	allowed := make(map[string]bool)
	if record.Result != nil {
		for _, host := range record.Result.Hosts {
			allowed[host.Target] = true
		}
	}
	for _, host := range result.VAReview.Hosts {
		if !allowed[host.Target] {
			record.Draxen = &vaDraxenReview{Status: "failed", Note: "Plano Draxen fora do escopo do recibo"}
			s.vaAppendEvent(record.ID, vaEvent{Stage: "draxen", Status: "failed", Detail: "Plano Draxen fora do escopo do recibo"})
			return
		}
		for _, raw := range host.ProposedActions {
			var action struct {
				Target      string `json:"target"`
				ActionClass string `json:"action_class"`
				Reason      string `json:"reason"`
			}
			if err := json.Unmarshal(raw, &action); err != nil || action.Target != host.Target || action.ActionClass != "active_read" {
				record.Draxen = &vaDraxenReview{Status: "failed", Note: "Proposta Draxen inválida"}
				s.vaAppendEvent(record.ID, vaEvent{Stage: "draxen", Status: "failed", Detail: "Proposta Draxen inválida"})
				return
			}
			s.vaAppendEvent(record.ID, vaEvent{Stage: "draxen", Status: "proposed", Target: host.Target, Detail: "Proposta para o SOC: " + shortVAChatText(action.Reason, 180)})
		}
		proposals += len(host.ProposedActions)
	}
	record.Draxen = &vaDraxenReview{Status: "completed", Offline: true, Artifacts: len(result.ArtifactAnalysis.Artifacts), Proposals: proposals, NetworkCalls: 0, Note: "Triagem e propostas offline; validação adicional depende do SOC"}
	s.vaAppendEvent(record.ID, vaEvent{Stage: "draxen", Status: "completed", Count: proposals, Detail: "Triagem offline e propostas de validação registradas; nenhuma requisição de rede"})
}
