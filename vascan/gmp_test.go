package vascan

import (
	"context"
	"encoding/xml"
	"net"
	"strings"
	"testing"
	"time"
)

const testGMPReport = `<get_reports_response status="200"><report><report><results><result><host>192.0.2.10</host><port>22/tcp</port><name>SSH test VT</name><description>Test observation</description><severity>7.5</severity><qod><value>80</value></qod><nvt oid="1.3.6.1.4.1.25623.1"><name>SSH test VT</name><cve>CVE-2026-1000</cve></nvt></result></results></report></report></get_reports_response>`

func TestParseGMPReportRequiresTargetAndConfidence(t *testing.T) {
	items, err := ParseGMPReport([]byte(testGMPReport), "192.0.2.10")
	if err != nil || len(items) != 1 || items[0].Check != "gmp.vt" || items[0].Severity != "high" {
		t.Fatalf("unexpected candidates: %#v %v", items, err)
	}
	if _, err := ParseGMPReport([]byte(testGMPReport), "192.0.2.11"); err == nil {
		t.Fatal("out-of-scope report accepted")
	}
	low := strings.Replace(testGMPReport, "<value>80</value>", "<value>20</value>", 1)
	items, err = ParseGMPReport([]byte(low), "192.0.2.10")
	if err != nil || len(items) != 0 {
		t.Fatalf("low QoD candidate accepted: %#v %v", items, err)
	}
}

func TestGMPScanHostProtocol(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	const targetID = "11111111-1111-4111-8111-111111111111"
	const taskID = "22222222-2222-4222-8222-222222222222"
	const reportID = "33333333-3333-4333-8333-333333333333"
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		dec := xml.NewDecoder(conn)
		responses := []string{
			`<authenticate_response status="200"/>`,
			`<create_target_response status="201" id="` + targetID + `"/>`,
			`<create_task_response status="201" id="` + taskID + `"/>`,
			`<start_task_response status="202"><report_id>` + reportID + `</report_id></start_task_response>`,
			`<get_tasks_response status="200"><task><status>Done</status><progress>100</progress></task></get_tasks_response>`,
			testGMPReport,
		}
		for _, response := range responses {
			var command struct{ XMLName xml.Name }
			if err := dec.Decode(&command); err != nil {
				done <- err
				return
			}
			if _, err := conn.Write([]byte(response)); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	cfg := GMPConfig{Address: listener.Addr().String(), Username: "test", Password: "test", ConfigID: targetID, ScannerID: taskID}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	report, err := GMPScanHost(ctx, cfg, "192.0.2.10", []int{22}, "0123456789abcdef01234567", nil)
	if err != nil || len(report.Candidates) != 1 || report.ReportID != reportID {
		t.Fatalf("GMP host report: %#v %v", report, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
