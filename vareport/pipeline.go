package vareport

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/MTheux/it4us-va/db"
	"github.com/MTheux/it4us-va/evidence"
)

// Result summarizes a generated VA report. The report is a draft for human
// review in SysReptor — it is not published.
type Result struct {
	ProjectID    string
	ProjectURL   string
	PDFPath      string
	FindingCount int
}

var reUnsafe = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

func slug(s string) string {
	s = reUnsafe.ReplaceAllString(strings.TrimSpace(s), "-")
	s = strings.Trim(s, "-")
	if s == "" {
		return "laudo-va"
	}
	return s
}

// Generate creates a SysReptor project from the VA design, pushes the findings
// VA-framed, renders a draft and exports the PDF to destDir. It fails closed:
// a finding written with exploitation language, or a render that returns any
// message (e.g. the "No anchor" pagination defect), aborts before a PDF is
// written. store may be nil, which skips dormant evidence staging.
func Generate(ctx context.Context, cli Client, store *evidence.Store, findings []*db.DBFinding, projectName, destDir string) (Result, error) {
	// 1. Map + VA-framing gate (fail-closed) before touching SysReptor.
	payloads := make([]FindingPayload, 0, len(findings))
	var framingErrs []string
	for _, f := range findings {
		p, err := ToFindingPayload(f)
		if err != nil {
			framingErrs = append(framingErrs, fmt.Sprintf("%q: %v", f.Name, err))
			continue
		}
		payloads = append(payloads, p)
	}
	if len(framingErrs) > 0 {
		return Result{}, fmt.Errorf("laudo VA bloqueado — %d finding(s) com enquadramento de pentest:\n%s",
			len(framingErrs), strings.Join(framingErrs, "\n"))
	}

	// 2. Create the project from the VA design.
	projectID, err := cli.CreateProject(ctx, projectName)
	if err != nil {
		return Result{}, fmt.Errorf("criar projeto SysReptor: %w", err)
	}

	// 3. Stage dormant evidence snapshots when a store is wired (optional).
	if store != nil && len(findings) > 0 {
		if err := store.StageFindingsExport(ctx, findings, destDir, true); err != nil {
			return Result{}, fmt.Errorf("stage de evidência: %w", err)
		}
	}

	// 4. Push findings.
	for _, p := range payloads {
		if err := cli.CreateFinding(ctx, projectID, p); err != nil {
			return Result{}, fmt.Errorf("criar finding %q: %w", p.Title, err)
		}
	}

	url := cli.ProjectURL(projectID)

	// 5. Render; refuse to export a non-clean report (pagination defect guard).
	rr, err := cli.Render(ctx, projectID)
	if err != nil {
		return Result{}, fmt.Errorf("render/check: %w", err)
	}
	if block := rr.Blocking(); len(block) > 0 {
		msgs := make([]string, len(block))
		for i, m := range block {
			msgs[i] = m.String()
		}
		return Result{ProjectID: projectID, ProjectURL: url, FindingCount: len(payloads)},
			fmt.Errorf("render com erro (laudo NÃO exportado, revisar projeto %s): %s", url, strings.Join(msgs, "; "))
	}

	// 6. Export the draft PDF.
	pdfPath := filepath.Join(destDir, slug(projectName)+".pdf")
	if err := cli.ExportPDF(ctx, projectID, pdfPath); err != nil {
		return Result{}, fmt.Errorf("exportar PDF: %w", err)
	}

	return Result{ProjectID: projectID, ProjectURL: url, PDFPath: pdfPath, FindingCount: len(payloads)}, nil
}
