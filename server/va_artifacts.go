package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// VA artifacts are written by the worker, never by a browser-supplied path.
// The event stream is append-only so an interrupted run retains its history.
type vaEvent struct {
	At     time.Time `json:"at"`
	Stage  string    `json:"stage"`
	Status string    `json:"status"`
	Target string    `json:"target,omitempty"`
	Detail string    `json:"detail,omitempty"`
	Count  int       `json:"count,omitempty"`
}

type vaFile struct {
	Path     string    `json:"path"`
	Name     string    `json:"name"`
	Size     int64     `json:"size"`
	Modified time.Time `json:"modified"`
	SHA256   string    `json:"sha256"`
}

func (s *Server) vaArtifactDir(id string) string {
	return filepath.Join(s.m.dir, "va-runs", "artifacts", id)
}

func (s *Server) vaSaveArtifact(id, name string, body []byte) error {
	if !validVARunID(id) || !validVAArtifactPath(name) || len(body) > 8<<20 {
		return errors.New("invalid VA artifact")
	}
	path := filepath.Join(s.vaArtifactDir(id), filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		return err
	}
	sum := sha256.Sum256(body)
	return os.WriteFile(path+".sha256", []byte(hex.EncodeToString(sum[:])), 0o600)
}

func (s *Server) vaAppendEvent(id string, event vaEvent) {
	if !validVARunID(id) {
		return
	}
	dir := s.vaArtifactDir(id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "[va] event directory: %v\n", err)
		return
	}
	event.At = time.Now().UTC()
	line, err := json.Marshal(event)
	if err != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(dir, "events.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[va] event open: %v\n", err)
		return
	}
	_, err = f.Write(append(line, '\n'))
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "[va] event write: %v\n", err)
	}
}

func validVAArtifactPath(name string) bool {
	if name == "plan.json" || name == "events.jsonl" || name == "receipt.json" {
		return true
	}
	parts := strings.Split(name, "/")
	if len(parts) != 2 || (parts[0] != "hosts" && parts[0] != "raw" && parts[0] != "deep") {
		return false
	}
	ext := ".json"
	if parts[0] == "raw" {
		ext = ".xml"
	}
	base := strings.TrimSuffix(parts[1], ext)
	if base == parts[1] || len(base) != 64 {
		return false
	}
	_, err := hex.DecodeString(base)
	return err == nil
}

func vaTargetArtifact(target, folder, extension string) string {
	sum := sha256.Sum256([]byte(target))
	return folder + "/" + hex.EncodeToString(sum[:]) + extension
}

func (s *Server) vaFiles(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validVARunID(id) {
		writeErr(w, http.StatusBadRequest, "invalid run ID")
		return
	}
	record, err := s.vaReadRecord(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "VA run not found")
		return
	}
	s.vaCurrent(&record)
	labels := map[string]string{"plan.json": "Plano aprovado", "events.jsonl": "Histórico de execução", "receipt.json": "Recibo final"}
	if record.Result != nil {
		for _, host := range record.Result.Hosts {
			labels[vaTargetArtifact(host.Target, "hosts", ".json")] = host.Target + " · inventário"
			labels[vaTargetArtifact(host.Target, "raw", ".xml")] = host.Target + " · scanner XML"
			labels[vaTargetArtifact(host.Target, "deep", ".json")] = host.Target + " · checks aprofundados"
		}
	}
	root := s.vaArtifactDir(id)
	files := make([]vaFile, 0)
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil || !validVAArtifactPath(filepath.ToSlash(rel)) {
			return nil
		}
		info, err := entry.Info()
		if err != nil || info.Size() > 8<<20 {
			return nil
		}
		hash, err := os.ReadFile(path + ".sha256")
		if err != nil {
			body, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil
			}
			sum := sha256.Sum256(body)
			hash = []byte(hex.EncodeToString(sum[:]))
		}
		name := labels[filepath.ToSlash(rel)]
		if name == "" {
			name = filepath.Base(rel)
		}
		files = append(files, vaFile{Path: filepath.ToSlash(rel), Name: name, Size: info.Size(), Modified: info.ModTime().UTC(), SHA256: string(hash)})
		return nil
	})
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	if _, err := os.Stat(filepath.Join(root, "receipt.json")); errors.Is(err, os.ErrNotExist) {
		body, _ := json.MarshalIndent(record, "", "  ")
		sum := sha256.Sum256(body)
		files = append(files, vaFile{Path: "receipt.json", Name: "Recibo da execução", Size: int64(len(body)), Modified: record.CreatedAt, SHA256: hex.EncodeToString(sum[:])})
		sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	}
	writeJSON(w, http.StatusOK, map[string]any{"files": files})
}

func (s *Server) vaFileContent(w http.ResponseWriter, r *http.Request) {
	id, name := r.PathValue("id"), r.URL.Query().Get("path")
	if !validVARunID(id) || !validVAArtifactPath(name) {
		writeErr(w, http.StatusBadRequest, "invalid artifact path")
		return
	}
	record, err := s.vaReadRecord(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "VA run not found")
		return
	}
	path := filepath.Join(s.vaArtifactDir(id), filepath.FromSlash(name))
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) && name == "receipt.json" {
		s.vaCurrent(&record)
		body, _ := json.MarshalIndent(record, "", "  ")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "private, no-store")
		_, _ = w.Write(body)
		return
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > 8<<20 {
		writeErr(w, http.StatusNotFound, "VA artifact not found")
		return
	}
	f, err := os.Open(path)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not open VA artifact")
		return
	}
	defer f.Close()
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "private, no-store")
	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("Content-Disposition", "attachment; filename=\""+filepath.Base(name)+"\"")
	}
	_, _ = io.Copy(w, io.LimitReader(f, 8<<20))
}

func (s *Server) vaEvents(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validVARunID(id) {
		writeErr(w, http.StatusBadRequest, "invalid run ID")
		return
	}
	if _, err := s.vaReadRecord(id); err != nil {
		writeErr(w, http.StatusNotFound, "VA run not found")
		return
	}
	f, err := os.Open(filepath.Join(s.vaArtifactDir(id), "events.jsonl"))
	if errors.Is(err, os.ErrNotExist) {
		writeJSON(w, http.StatusOK, map[string]any{"events": []vaEvent{}})
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not read VA history")
		return
	}
	defer f.Close()
	dec := json.NewDecoder(io.LimitReader(f, 8<<20))
	events := make([]vaEvent, 0)
	for len(events) < 10000 {
		var event vaEvent
		if err := dec.Decode(&event); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			break
		}
		events = append(events, event)
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

func vaCanonicalTarget(target string) bool {
	ip, err := netip.ParseAddr(target)
	return err == nil && !ip.Is4In6() && ip.String() == target
}
