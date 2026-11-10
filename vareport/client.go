package vareport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
	"time"
)

// Config holds SysReptor connection settings. The caller reads these from env.
type Config struct {
	BaseURL  string // e.g. http://127.0.0.1:8000
	Token    string // SysReptor API token
	DesignID string // project type (design) UUID for VA reports
}

// FindingPayload is the VA-framed finding sent to SysReptor. Severity is already
// normalized (see NormalizeSeverity). Description carries the observed condition
// plus read-only evidence — never exploitation steps.
type FindingPayload struct {
	Title              string
	Severity           string
	Summary            string
	Impact             string
	Description        string
	Recommendation     string
	AffectedComponents []string
	References         []string
	RetestStatus       string
}

// RenderResult carries the messages SysReptor returns when checking a project.
// A non-empty Messages after a VA render means the report is not clean (e.g. the
// "No anchor" pagination defect) and must not be shipped.
type RenderResult struct {
	Messages []string
}

// Client talks to SysReptor. Isolated behind an interface so the pipeline is
// testable against a fake.
type Client interface {
	CreateProject(ctx context.Context, name string) (projectID string, err error)
	CreateFinding(ctx context.Context, projectID string, f FindingPayload) error
	UploadImage(ctx context.Context, projectID, name string, data []byte) (ref string, err error)
	Render(ctx context.Context, projectID string) (RenderResult, error)
	ExportPDF(ctx context.Context, projectID, dest string) error
	ProjectURL(projectID string) string
}

type httpClient struct {
	cfg Config
	hc  *http.Client
}

// NewHTTPClient returns a Client backed by the SysReptor REST API.
func NewHTTPClient(cfg Config) Client {
	return &httpClient{cfg: cfg, hc: &http.Client{Timeout: 60 * time.Second}}
}

func (c *httpClient) ProjectURL(projectID string) string {
	return strings.TrimRight(c.cfg.BaseURL, "/") + "/projects/" + projectID + "/"
}

func (c *httpClient) url(path string) string {
	return strings.TrimRight(c.cfg.BaseURL, "/") + path
}

func (c *httpClient) do(ctx context.Context, method, path string, body io.Reader, contentType string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.url(path), body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return c.hc.Do(req)
}

func (c *httpClient) CreateProject(ctx context.Context, name string) (string, error) {
	body, _ := json.Marshal(map[string]any{"name": name, "project_type": c.cfg.DesignID})
	resp, err := c.do(ctx, http.MethodPost, "/api/v1/pentestprojects/", bytes.NewReader(body), "application/json")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return "", httpErr("create project", resp)
	}
	var out struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if out.ID == "" {
		return "", fmt.Errorf("create project: empty id in response")
	}
	return out.ID, nil
}

func (c *httpClient) CreateFinding(ctx context.Context, projectID string, f FindingPayload) error {
	payload := map[string]any{
		"data": map[string]any{
			"title":               f.Title,
			"severity":            f.Severity,
			"summary":             f.Summary,
			"impact":              f.Impact,
			"description":         f.Description,
			"recommendation":      f.Recommendation,
			"affected_components": f.AffectedComponents,
			"references":          f.References,
			"retest_status":       f.RetestStatus,
		},
		"status":   "in-progress",
		"language": "pt-PT",
	}
	body, _ := json.Marshal(payload)
	resp, err := c.do(ctx, http.MethodPost, "/api/v1/pentestprojects/"+projectID+"/findings/", bytes.NewReader(body), "application/json")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return httpErr("create finding", resp)
	}
	return nil
}

func (c *httpClient) UploadImage(ctx context.Context, projectID, name string, data []byte) (string, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", name)
	if err != nil {
		return "", err
	}
	if _, err := fw.Write(data); err != nil {
		return "", err
	}
	mw.Close()
	resp, err := c.do(ctx, http.MethodPost, "/api/v1/pentestprojects/"+projectID+"/images/", &buf, mw.FormDataContentType())
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return "", httpErr("upload image", resp)
	}
	var out struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.Name, nil
}

func (c *httpClient) Render(ctx context.Context, projectID string) (RenderResult, error) {
	resp, err := c.do(ctx, http.MethodPost, "/api/v1/pentestprojects/"+projectID+"/check/", nil, "application/json")
	if err != nil {
		return RenderResult{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return RenderResult{}, httpErr("render/check", resp)
	}
	var out struct {
		Messages []struct {
			Level   string `json:"level"`
			Message string `json:"message"`
		} `json:"messages"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return RenderResult{}, err
	}
	var res RenderResult
	for _, m := range out.Messages {
		res.Messages = append(res.Messages, strings.TrimSpace(m.Level+": "+m.Message))
	}
	return res, nil
}

func (c *httpClient) ExportPDF(ctx context.Context, projectID, dest string) error {
	resp, err := c.do(ctx, http.MethodPost, "/api/v1/pentestprojects/"+projectID+"/generate/", nil, "application/json")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return httpErr("export pdf", resp)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	return os.WriteFile(dest, data, 0o644)
}

func httpErr(op string, resp *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	return fmt.Errorf("%s: HTTP %d: %s", op, resp.StatusCode, strings.TrimSpace(string(b)))
}
