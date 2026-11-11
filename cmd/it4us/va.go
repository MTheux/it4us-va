package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/MTheux/it4us-va/config"
	"github.com/MTheux/it4us-va/db"
	"github.com/MTheux/it4us-va/vascan"
)

// runVA supports the first operational VA workflow from a SOC terminal. The
// campaign file is the single approval surface for its targets and time window.
func runVA(args []string) int {
	if len(args) == 0 || args[0] != "scan" {
		fmt.Fprintln(os.Stderr, "usage: it4us va scan --campaign FILE --task-id ID [--out DIR] [--dry-run|--record-only]")
		return 2
	}
	fs := flag.NewFlagSet("va scan", flag.ContinueOnError)
	campaignPath := fs.String("campaign", "", "approved campaign JSON")
	taskID := fs.Int64("task-id", 0, "existing IT4US VA task ID")
	outDir := fs.String("out", filepath.Join(config.BaseDir(), "data", "va-runs"), "private result directory")
	dryRun := fs.Bool("dry-run", false, "validate campaign and print the execution plan without scanning")
	recordOnly := fs.Bool("record-only", false, "run the scanner and save a private receipt without PostgreSQL (lab validation)")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || *campaignPath == "" || *taskID <= 0 {
		fmt.Fprintln(os.Stderr, "usage: it4us va scan --campaign FILE --task-id ID [--out DIR] [--dry-run|--record-only]")
		return 2
	}
	if *dryRun && *recordOnly {
		fmt.Fprintln(os.Stderr, "--dry-run and --record-only cannot be combined")
		return 2
	}
	c, err := vascan.LoadCampaign(*campaignPath, time.Now())
	if err != nil {
		log.Printf("[va] campaign: %v", err)
		return 1
	}
	if c.TaskID != *taskID {
		log.Printf("[va] task_id in campaign (%d) differs from --task-id (%d)", c.TaskID, *taskID)
		return 1
	}
	if *dryRun {
		targets, _ := c.ExpandedTargets()
		fmt.Printf("Campanha %q: %d IP(s), %d porta(s), tarefa %d, expira %s\n", c.Name, len(targets), len(c.Ports), *taskID, c.ExpiresAt.Format(time.RFC3339))
		fmt.Printf("  Portas TCP: %v\n", c.Ports)
		for _, target := range targets {
			fmt.Println("  " + target)
		}
		return 0
	}
	var pg *db.DB
	if !*recordOnly {
		dsn, _, err := config.PostgresDSN()
		if err != nil {
			log.Printf("[va] PostgreSQL: %v", err)
			return 1
		}
		pg, err = db.Open(dsn)
		if err != nil {
			log.Printf("[va] PostgreSQL: %v", err)
			return 1
		}
		defer pg.Close()
		task, err := pg.GetTask(*taskID)
		if err != nil || task == nil {
			log.Printf("[va] tarefa %d indisponível: %v", *taskID, err)
			return 1
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	result, runErr := vascan.Run(ctx, c, vascan.NmapScanner{}, time.Now)
	path, saveErr := saveVAResult(*outDir, result)
	if saveErr != nil {
		log.Printf("[va] salvar resultado: %v", saveErr)
		return 1
	}
	fmt.Printf("Resultado da campanha: %s\n", path)
	if runErr != nil {
		log.Printf("[va] execução interrompida: %v", runErr)
		return 1
	}
	failed := 0
	for _, h := range result.Hosts {
		if h.Status != "completed" {
			failed++
		}
	}
	if *recordOnly {
		fmt.Printf("Hosts: %d; checks falhos: %d; recibo local salvo sem persistência no banco\n", len(result.Hosts), failed)
		if failed > 0 {
			return 1
		}
		return 0
	}
	count, err := vascan.Persist(pg, *taskID, result)
	if err != nil {
		log.Printf("[va] persistência parcial após %d candidatos: %v", count, err)
		return 1
	}
	fmt.Printf("Hosts: %d; checks falhos: %d; candidatos pendentes para revisão: %d\n", len(result.Hosts), failed, count)
	if failed > 0 {
		return 1
	}
	return 0
}

func saveVAResult(dir string, result vascan.Result) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	seed := make([]byte, 4)
	if _, err := rand.Read(seed); err != nil {
		return "", err
	}
	name := "va-" + time.Now().UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(seed) + ".json"
	path := filepath.Join(dir, name)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		f.Close()
		os.Remove(path)
		return "", err
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return "", err
	}
	return path, nil
}
