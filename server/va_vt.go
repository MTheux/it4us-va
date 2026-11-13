package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/MTheux/it4us-va/vascan"
)

func vaVTEnabled() bool { return os.Getenv("IT4US_VA_VT_ENABLED") == "1" }

func vaVTConfig() vascan.GMPConfig {
	return vascan.GMPConfig{
		Address:   os.Getenv("IT4US_GMP_ADDR"),
		Username:  os.Getenv("IT4US_GMP_USERNAME"),
		Password:  os.Getenv("IT4US_GMP_PASSWORD"),
		ConfigID:  os.Getenv("IT4US_GMP_CONFIG_ID"),
		ScannerID: os.Getenv("IT4US_GMP_SCANNER_ID"),
	}
}

// The VT phase receives only ports actually observed in discovery and uses a
// distinct one-host task. A task-scope change aborts the remote scan on the next
// progress poll; no new host is ever added by the manager's report.
func (s *Server) vaEnrichWithVT(ctx context.Context, record vaRunRecord, result *vascan.Result) error {
	if !vaVTEnabled() || record.Campaign.Depth != "deep" {
		return nil
	}
	cfg := vaVTConfig()
	if err := cfg.Validate(); err != nil {
		return err
	}
	scoped := vaScopedScanner{pg: s.m.PG(), taskID: record.Campaign.TaskID}
	for i := range result.Hosts {
		host := &result.Hosts[i]
		if host.Status != "completed" {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if !time.Now().Before(record.Campaign.ExpiresAt) {
			return errors.New("campaign expired during VT phase")
		}
		if err := scoped.allowed(host.Target); err != nil {
			return fmt.Errorf("VA scope revoked before VT check %s: %w", host.Target, err)
		}
		seen := map[int]bool{}
		ports := make([]int, 0)
		for _, service := range host.Services {
			if service.Port > 0 && service.Port <= 65535 && !seen[service.Port] {
				seen[service.Port] = true
				ports = append(ports, service.Port)
			}
		}
		sort.Ints(ports)
		if len(ports) == 0 {
			continue
		}
		if len(ports) > 32 {
			ports = ports[:32]
			host.DeepError = strings.TrimSpace(host.DeepError + "; VT port budget reached (32 observed TCP ports)")
		}
		s.vaAppendEvent(record.ID, vaEvent{Stage: "vt", Status: "started", Target: host.Target, Count: len(ports), Detail: "Verificações de vulnerabilidade em portas observadas"})
		deadline := record.Campaign.ExpiresAt
		if hostLimit := time.Now().Add(15 * time.Minute); hostLimit.Before(deadline) {
			deadline = hostLimit
		}
		vtCtx, cancel := context.WithDeadline(ctx, deadline)
		lastState := ""
		report, err := vascan.GMPScanHost(vtCtx, cfg, host.Target, ports, record.ID, func(state string) error {
			if err := scoped.allowed(host.Target); err != nil {
				return err
			}
			if state != lastState {
				s.vaAppendEvent(record.ID, vaEvent{Stage: "vt", Status: "running", Target: host.Target, Detail: shortVAChatText(state, 100)})
				lastState = state
			}
			return nil
		})
		cancel()
		if err != nil {
			host.DeepError = strings.TrimSpace(host.DeepError + "; VT: " + err.Error())
			s.vaAppendEvent(record.ID, vaEvent{Stage: "vt", Status: "failed", Target: host.Target, Detail: "Verificações não concluídas; cobertura parcial"})
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if !time.Now().Before(record.Campaign.ExpiresAt) {
				return errors.New("campaign expired during VT phase")
			}
			continue
		}
		if err := s.vaSaveArtifact(record.ID, vaTargetArtifact(host.Target, "vt", ".xml"), report.Raw); err != nil {
			host.DeepError = strings.TrimSpace(host.DeepError + "; VT report not persisted")
			s.vaAppendEvent(record.ID, vaEvent{Stage: "vt", Status: "failed", Target: host.Target, Detail: "Relatório de VTs não preservado"})
			continue
		}
		host.Candidates = append(host.Candidates, report.Candidates...)
		body, _ := json.MarshalIndent(host, "", "  ")
		_ = s.vaSaveArtifact(record.ID, vaTargetArtifact(host.Target, "hosts", ".json"), body)
		s.vaAppendEvent(record.ID, vaEvent{Stage: "vt", Status: "completed", Target: host.Target, Count: len(report.Candidates), Detail: "Candidatos de VT registrados para triagem"})
	}
	return nil
}
