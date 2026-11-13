package vascan

import (
	"fmt"
	"net"
	"strings"

	"github.com/MTheux/it4us-va/db"
)

// Persist links observed hosts and pending candidates to an existing task.
// Findings remain pending for SOC review; a scanner result is never promoted
// directly to a confirmed vulnerability. The returned count is observations
// in this campaign, including candidates previously seen in the same task.
func Persist(pg *db.DB, taskID int64, result Result) (int, error) {
	if pg == nil || taskID <= 0 {
		return 0, fmt.Errorf("database and task_id are required")
	}
	task, err := pg.GetTask(taskID)
	if err != nil {
		return 0, err
	}
	if task == nil {
		return 0, fmt.Errorf("task %d does not exist", taskID)
	}
	count := 0
	for _, host := range result.Hosts {
		if host.Status != "completed" {
			continue
		}
		ip := net.ParseIP(host.Target)
		if ip == nil {
			return count, fmt.Errorf("invalid result target %q", host.Target)
		}
		ipID, err := pg.Assets().UpsertIP(db.UpsertIPReq{IP: host.Target, TaskID: taskID})
		if err != nil {
			return count, err
		}
		for _, service := range host.Services {
			if service.IP == "" || !ip.Equal(net.ParseIP(service.IP)) || service.Port < 1 || service.Port > 65535 {
				return count, fmt.Errorf("invalid service in scanned host %s", host.Target)
			}
			name := strings.TrimSpace(service.Service)
			if name == "" {
				name = "unknown"
			}
			if _, err := pg.Assets().UpsertOtherService(db.UpsertOtherServiceReq{
				IP: host.Target, Port: service.Port, ServiceName: name, TaskID: taskID,
			}); err != nil {
				return count, err
			}
		}
		for _, candidate := range host.Candidates {
			if (candidate.Check != "nmap.service" && candidate.Check != "nmap.ssl-cert" && candidate.Check != "nmap.smb2-security-mode" && candidate.Check != "gmp.vt") || candidate.Asset.IP == "" || !ip.Equal(net.ParseIP(candidate.Asset.IP)) {
				return count, fmt.Errorf("candidate target does not match scanned host %s", host.Target)
			}
			severity := strings.ToLower(candidate.Severity)
			if !db.ValidSeverity(severity) {
				return count, fmt.Errorf("invalid candidate severity %q", candidate.Severity)
			}
			assetIDs := []int64{ipID}
			if candidate.Asset.Port > 0 && candidate.Asset.Service != "" {
				serviceID, err := pg.Assets().UpsertOtherService(db.UpsertOtherServiceReq{
					IP: host.Target, Port: candidate.Asset.Port, ServiceName: candidate.Asset.Service, TaskID: taskID,
				})
				if err != nil {
					return count, err
				}
				assetIDs = append(assetIDs, serviceID)
			}
			_, _, err := pg.AddVACandidate(taskID, ipID, candidate.VulnClass, candidate.Title, severity,
				candidate.Summary, candidate.Evidence, assetIDs)
			if err != nil {
				return count, err
			}
			count++
		}
	}
	return count, nil
}
