package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/MTheux/it4us-va/config"
	"github.com/MTheux/it4us-va/db"
	"github.com/MTheux/it4us-va/vareport"
)

// runReport implements `it4us report --task-id ID [nome]`: gera um laudo de VA rascunho no
// SysReptor a partir dos findings do store e PARA para revisão humana — não
// publica. Fail-closed: qualquer problema de config/API devolve código != 0 sem
// efeito colateral parcial relevante (o projeto rascunho fica no SysReptor para
// inspeção quando o render acusa defeito).
func runReport(args []string) int {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	taskID := fs.Int64("task-id", 0, "tarefa cujos achados compõem o laudo")
	if err := fs.Parse(args); err != nil || *taskID <= 0 {
		fmt.Fprintln(os.Stderr, "usage: it4us report --task-id ID [nome]")
		return 2
	}
	cfg, err := vareport.ConfigFromEnv()
	if err != nil {
		log.Printf("[report] %v", err)
		return 1
	}
	dsn, _, err := config.PostgresDSN()
	if err != nil {
		log.Printf("[report] DSN: %v", err)
		return 1
	}
	pg, err := db.Open(dsn)
	if err != nil {
		log.Printf("[report] abrir banco: %v", err)
		return 1
	}
	defer pg.Close()
	task, err := pg.GetTask(*taskID)
	if err != nil || task == nil {
		log.Printf("[report] tarefa %d indisponível: %v", *taskID, err)
		return 1
	}

	findings, err := pg.ListFindingsForExport(db.FindingFilter{TaskID: strconv.FormatInt(*taskID, 10), Status: db.FindingConfirmed}, nil)
	if err != nil {
		log.Printf("[report] listar findings: %v", err)
		return 1
	}

	name := strings.TrimSpace(strings.Join(fs.Args(), " "))
	if name == "" {
		name = "Avaliação de Vulnerabilidades " + time.Now().Format("2006-01-02")
	}
	destDir := strings.TrimSpace(os.Getenv("IT4US_REPORT_DIR"))
	if destDir == "" {
		destDir = filepath.Join(config.BaseDir(), "data", "reports")
	}
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		log.Printf("[report] criar diretório de saída: %v", err)
		return 1
	}

	cli := vareport.NewHTTPClient(cfg)
	res, err := vareport.Generate(context.Background(), cli, nil, findings, name, destDir)
	if err != nil {
		log.Printf("[report] geração falhou (fail-closed): %v", err)
		return 1
	}

	fmt.Printf("\nLaudo VA rascunho gerado — revisão humana pendente (não publicado):\n")
	fmt.Printf("  projeto SysReptor: %s\n", res.ProjectURL)
	fmt.Printf("  PDF rascunho:      %s\n", res.PDFPath)
	fmt.Printf("  findings:          %d\n", res.FindingCount)
	return 0
}
