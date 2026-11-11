package main

import (
	"context"
	"testing"

	"github.com/MTheux/it4us-va/agent"
)

func TestShutdownContextPreservesNamedCause(t *testing.T) {
	signalCtx, signalCancel := context.WithCancel(context.Background())
	ctx, shutdown := shutdownContext(signalCtx)
	defer shutdown(nil)
	signalCancel()
	<-ctx.Done()
	if code, _, _, ok := agent.AbortReason(ctx); !ok || code != "shutdown" {
		t.Fatalf("code=%q ok=%v, want shutdown", code, ok)
	}
}

func TestReportRequiresTaskFilterBeforeDatabaseAccess(t *testing.T) {
	if got := runReport(nil); got != 2 {
		t.Fatalf("runReport without task returned %d, want 2", got)
	}
}
