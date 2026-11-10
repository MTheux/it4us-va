package vareport

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/MTheux/it4us-va/db"
)

type fakeClient struct {
	created   []FindingPayload
	projectID string
	renderMsg []RenderMessage
	pdfPath   string
}

func (f *fakeClient) CreateProject(ctx context.Context, name string) (string, error) {
	if f.projectID == "" {
		f.projectID = "proj-x"
	}
	return f.projectID, nil
}
func (f *fakeClient) CreateFinding(ctx context.Context, projectID string, p FindingPayload) error {
	f.created = append(f.created, p)
	return nil
}
func (f *fakeClient) UploadImage(ctx context.Context, projectID, name string, data []byte) (string, error) {
	return name, nil
}
func (f *fakeClient) Render(ctx context.Context, projectID string) (RenderResult, error) {
	return RenderResult{Messages: f.renderMsg}, nil
}
func (f *fakeClient) ExportPDF(ctx context.Context, projectID, dest string) error {
	f.pdfPath = dest
	return os.WriteFile(dest, []byte("%PDF fake"), 0o644)
}
func (f *fakeClient) ProjectURL(projectID string) string {
	return "http://sr/projects/" + projectID + "/"
}

func TestGenerateCreatesProjectAndFindings(t *testing.T) {
	fc := &fakeClient{}
	findings := []*db.DBFinding{
		{Name: "TLS fraco", VulnClass: "tls.weak", Severity: "medium", Summary: "aceita TLS 1.0"},
		{Name: "SMB share", VulnClass: "shares.open", Severity: "high", Summary: "share anônimo"},
	}
	res, err := Generate(context.Background(), fc, nil, findings, "VA ACME", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if res.FindingCount != 2 || len(fc.created) != 2 {
		t.Errorf("findings=%d created=%d", res.FindingCount, len(fc.created))
	}
	if !strings.HasSuffix(res.PDFPath, ".pdf") || res.ProjectURL == "" {
		t.Errorf("res=%+v", res)
	}
}

func TestGenerateZeroFindings(t *testing.T) {
	fc := &fakeClient{}
	res, err := Generate(context.Background(), fc, nil, nil, "VA vazio", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if res.FindingCount != 0 || len(fc.created) != 0 {
		t.Errorf("esperava 0 findings, got %d/%d", res.FindingCount, len(fc.created))
	}
	if _, statErr := os.Stat(res.PDFPath); statErr != nil {
		t.Errorf("PDF não gerado no caso zero: %v", statErr)
	}
}

func TestGenerateFailsOnRenderMessages(t *testing.T) {
	fc := &fakeClient{renderMsg: []RenderMessage{{Level: "warning", Message: "No anchor #uuid"}}}
	findings := []*db.DBFinding{{Name: "x", VulnClass: "c", Severity: "low", Summary: "s"}}
	_, err := Generate(context.Background(), fc, nil, findings, "VA bug", t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "No anchor") {
		t.Fatalf("esperava erro de render com 'No anchor', got %v", err)
	}
	if fc.pdfPath != "" {
		t.Error("PDF não deveria ter sido exportado com render sujo")
	}
}

func TestGenerateIgnoresBenignWarnings(t *testing.T) {
	// "Empty field" (metadados não preenchidos) é warning benigno: não deve
	// impedir a geração do rascunho — o humano preenche na revisão.
	fc := &fakeClient{renderMsg: []RenderMessage{{Level: "warning", Message: "Empty field", Location: "Projeto/start_date"}}}
	findings := []*db.DBFinding{{Name: "TLS fraco", VulnClass: "tls.weak", Severity: "low", Summary: "s"}}
	res, err := Generate(context.Background(), fc, nil, findings, "VA ok", t.TempDir())
	if err != nil {
		t.Fatalf("warning benigno não deveria bloquear: %v", err)
	}
	if _, statErr := os.Stat(res.PDFPath); statErr != nil {
		t.Errorf("PDF não gerado apesar de warning benigno: %v", statErr)
	}
}

func TestGenerateBlocksExploitationFraming(t *testing.T) {
	fc := &fakeClient{}
	findings := []*db.DBFinding{{Name: "rce", VulnClass: "rce", Severity: "high", Summary: "ok", Report: "exploramos e obtivemos shell"}}
	_, err := Generate(context.Background(), fc, nil, findings, "VA", t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "enquadramento de pentest") {
		t.Fatalf("esperava bloqueio por enquadramento, got %v", err)
	}
	if len(fc.created) != 0 {
		t.Error("não deveria criar finding com enquadramento de pentest")
	}
}
