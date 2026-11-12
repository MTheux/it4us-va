"use client";

import * as React from "react";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { ArrowLeftIcon, ArrowRightIcon, GitBranchIcon, ShieldAlertIcon } from "lucide-react";
import { toast } from "sonner";

import { CopyButton } from "@/components/copy-button";
import { Markdown } from "@/components/markdown";
import { StatusBadge } from "@/components/status-badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger } from "@/components/ui/select";
import { api } from "@/lib/api";
import { statusMeta } from "@/lib/status";
import type { Finding, FindingStatus, Severity } from "@/lib/types";

import { FindingLineageView } from "./lineage";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];
const FINDING_STATUSES: FindingStatus[] = [
  "pending",
  "in_progress",
  "confirmed",
  "resolved",
  "fixed",
  "false_positive",
  "ignored",
  "duplicate",
  "risk_accepted",
];

function fmtTime(ts: string) {
  const date = new Date(ts);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString("pt-BR", { dateStyle: "short", timeStyle: "short" });
}

function FindingDetailInner() {
  const searchParams = useSearchParams();
  const id = searchParams.get("id") ?? "";
  const contextTaskId = searchParams.get("context_task") ?? "";
  const [finding, setFinding] = React.useState<Finding | null>(null);
  const [loaded, setLoaded] = React.useState(false);
  const [view, setView] = React.useState<"overview" | "lineage">("overview");
  const [hasLineage, setHasLineage] = React.useState(false);
  const [lineageLoaded, setLineageLoaded] = React.useState(false);

  const load = React.useCallback(() => {
    if (!id) {
      setLoaded(true);
      return;
    }
    api
      .getFinding(id, contextTaskId || undefined)
      .then(setFinding)
      .catch(() => setFinding(null))
      .finally(() => setLoaded(true));
  }, [contextTaskId, id]);

  React.useEffect(() => {
    load();
  }, [load]);
  React.useEffect(() => {
    if (!id) return;
    let active = true;
    setHasLineage(false);
    setLineageLoaded(false);
    setView("overview");
    void api
      .findingLineage(id)
      .then((graph) => {
        if (active) setHasLineage((graph.nodes?.length ?? 0) > 0);
      })
      .catch(() => {
        if (active) setHasLineage(false);
      })
      .finally(() => {
        if (active) setLineageLoaded(true);
      });
    return () => {
      active = false;
    };
  }, [id]);

  async function changeSeverity(next: Severity) {
    if (!finding || finding.inherited || next === finding.severity) return;
    const previous = finding.severity;
    setFinding({ ...finding, severity: next });
    try {
      setFinding(await api.setFindingSeverity(id, next));
      toast.success(`Severidade alterada para ${statusMeta("severity", next).label}.`);
    } catch (error) {
      setFinding((current) => (current ? { ...current, severity: previous } : current));
      toast.error("Não foi possível alterar a severidade: " + (error as Error).message);
    }
  }

  async function changeStatus(next: FindingStatus) {
    if (!finding || finding.inherited || next === finding.status) return;
    const previous = finding.status;
    setFinding({ ...finding, status: next });
    try {
      setFinding(await api.setFindingStatus(id, next));
      toast.success(`Estado alterado para ${statusMeta("finding", next).label}.`);
    } catch (error) {
      setFinding((current) => (current ? { ...current, status: previous } : current));
      toast.error("Não foi possível alterar o estado: " + (error as Error).message);
    }
  }

  if (!finding)
    return (
      <div className="flex min-h-[60vh] flex-col items-center justify-center gap-3 p-10 text-center">
        <p className="text-sm text-muted-foreground">
          {loaded ? `Achado #${id} não encontrado.` : "Carregando achado…"}
        </p>
        {loaded && (
          <Button asChild variant="outline">
            <Link href="/function/findings">
              <ArrowLeftIcon /> Voltar aos achados
            </Link>
          </Button>
        )}
      </div>
    );

  const title = finding.name || finding.vulnclass || `Achado #${finding.id}`;
  const demo = title.startsWith("[DEMO]") || finding.evidence?.startsWith("DADO FICTICIO");

  return (
    <main data-content-padding="false" className="mx-auto w-full max-w-7xl space-y-6 px-4 py-6 lg:px-10">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <Button asChild variant="ghost" size="sm" className="-ml-2">
          <Link href="/function/findings">
            <ArrowLeftIcon /> Achados
          </Link>
        </Button>
        <span className="font-mono text-xs text-muted-foreground">#{finding.id}</span>
      </div>

      <header className="border-b pb-6">
        <p className="font-mono text-[11px] font-medium uppercase tracking-[0.2em] text-primary">SOC / TRIAGEM</p>
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <h1 className="min-w-0 font-[family-name:var(--font-display)] text-3xl font-semibold tracking-tight sm:text-4xl">
            {title}
          </h1>
          {demo && <Badge variant="secondary">Dado fictício</Badge>}
        </div>
        <div className="mt-3 flex flex-wrap gap-2">
          <StatusBadge domain="severity" value={finding.severity} dot />
          <StatusBadge domain="finding" value={finding.status} dot />
          {finding.inherited && <Badge variant="outline">Herdado · somente leitura</Badge>}
        </div>
        <p className="mt-4 max-w-3xl text-sm leading-6 text-muted-foreground">
          {finding.summary || "Este achado ainda não tem um resumo registrado."}
        </p>
      </header>

      <div
        className="flex flex-wrap items-center gap-2 border-b pb-3"
        role="tablist"
        aria-label="Visualizações do achado"
      >
        <button
          type="button"
          role="tab"
          aria-selected={view === "overview"}
          onClick={() => setView("overview")}
          className={
            view === "overview"
              ? "rounded-lg border border-primary bg-primary/10 px-3 py-2 text-sm font-medium text-primary"
              : "rounded-lg border px-3 py-2 text-sm text-muted-foreground hover:text-foreground"
          }
        >
          Visão geral
        </button>
        {hasLineage && (
          <button
            type="button"
            role="tab"
            aria-selected={view === "lineage"}
            onClick={() => setView("lineage")}
            className={
              view === "lineage"
                ? "rounded-lg border border-primary bg-primary/10 px-3 py-2 text-sm font-medium text-primary"
                : "rounded-lg border px-3 py-2 text-sm text-muted-foreground hover:text-foreground"
            }
          >
            <GitBranchIcon className="mr-1 inline size-4" /> Grafo de exploração
          </button>
        )}
      </div>

      {view === "lineage" && hasLineage ? (
        <section aria-label="Grafo de exploração" className="overflow-hidden rounded-xl border bg-card/50 p-2">
          <FindingLineageView findingId={finding.id} />
        </section>
      ) : (
        <div className="grid gap-4 lg:grid-cols-[minmax(0,1.5fr)_minmax(17rem,0.75fr)]">
          <div className="min-w-0 space-y-4">
            <section className="rounded-xl border bg-card/50 p-5" aria-labelledby="evidence-heading">
              <div className="flex items-center justify-between gap-2">
                <div>
                  <p className="font-mono text-[10px] uppercase tracking-widest text-primary">VALIDAÇÃO</p>
                  <h2 id="evidence-heading" className="mt-1 text-lg font-semibold">
                    Evidência registrada
                  </h2>
                </div>
                <ShieldAlertIcon className="size-5 text-primary" />
              </div>
              {finding.evidence ? (
                <pre className="mt-4 max-h-[48vh] overflow-auto rounded-lg border bg-background/70 p-4 font-mono text-xs leading-5 whitespace-pre-wrap break-words">
                  {finding.evidence}
                </pre>
              ) : (
                <p className="mt-4 text-sm text-muted-foreground">Nenhuma evidência registrada.</p>
              )}
              {demo && (
                <p className="mt-3 text-xs text-muted-foreground">
                  Exemplo visual. Nenhuma resposta do alvo foi coletada.
                </p>
              )}
            </section>
            <section className="rounded-xl border bg-card/50 p-5" aria-labelledby="report-heading">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <p className="font-mono text-[10px] uppercase tracking-widest text-primary">DOCUMENTAÇÃO</p>
                  <h2 id="report-heading" className="mt-1 text-lg font-semibold">
                    Relatório detalhado
                  </h2>
                </div>
                {finding.report && <CopyButton text={finding.report} successMessage="Relatório copiado" />}
              </div>
              {finding.report_stale && (
                <Alert className="mt-4">
                  <AlertDescription>A evidência de tráfego mudou; o relatório aguarda atualização.</AlertDescription>
                </Alert>
              )}
              {finding.report ? (
                <div className="mt-4">
                  <Markdown text={finding.report} />
                </div>
              ) : (
                <p className="mt-4 text-sm text-muted-foreground">Ainda não há relatório detalhado para este achado.</p>
              )}
            </section>
          </div>

          <aside className="min-w-0 space-y-4">
            <section className="rounded-xl border bg-card/50 p-5" aria-labelledby="triage-heading">
              <p className="font-mono text-[10px] uppercase tracking-widest text-primary">OPERAÇÃO</p>
              <h2 id="triage-heading" className="mt-1 text-lg font-semibold">
                Triagem
              </h2>
              <div className="mt-4 space-y-4 border-t pt-4">
                <div className="space-y-1.5">
                  <p className="text-xs text-muted-foreground">Severidade</p>
                  {finding.inherited ? (
                    <StatusBadge domain="severity" value={finding.severity} dot />
                  ) : (
                    <Select value={finding.severity} onValueChange={(value) => void changeSeverity(value as Severity)}>
                      <SelectTrigger className="w-full">
                        <StatusBadge domain="severity" value={finding.severity} dot />
                      </SelectTrigger>
                      <SelectContent position="popper" align="end">
                        <SelectGroup>
                          {SEVERITIES.map((severity) => (
                            <SelectItem key={severity} value={severity}>
                              {statusMeta("severity", severity).label}
                            </SelectItem>
                          ))}
                        </SelectGroup>
                      </SelectContent>
                    </Select>
                  )}
                </div>
                <div className="space-y-1.5">
                  <p className="text-xs text-muted-foreground">Estado</p>
                  {finding.inherited ? (
                    <StatusBadge domain="finding" value={finding.status} dot />
                  ) : (
                    <Select value={finding.status} onValueChange={(value) => void changeStatus(value as FindingStatus)}>
                      <SelectTrigger className="w-full">
                        <StatusBadge domain="finding" value={finding.status} dot />
                      </SelectTrigger>
                      <SelectContent position="popper" align="end">
                        <SelectGroup>
                          {FINDING_STATUSES.map((status) => (
                            <SelectItem key={status} value={status}>
                              {statusMeta("finding", status).label}
                            </SelectItem>
                          ))}
                        </SelectGroup>
                      </SelectContent>
                    </Select>
                  )}
                </div>
              </div>
            </section>
            <section className="rounded-xl border bg-card/50 p-5" aria-label="Contexto do achado">
              <p className="font-mono text-[10px] uppercase tracking-widest text-primary">CONTEXTO</p>
              <h2 className="mt-1 text-lg font-semibold">Origem e ativos</h2>
              <dl className="mt-4 divide-y border-t text-sm">
                <div className="flex flex-wrap justify-between gap-2 py-3">
                  <dt className="text-muted-foreground">Classe</dt>
                  <dd className="min-w-0 break-all font-mono text-xs">{finding.vulnclass || "—"}</dd>
                </div>
                <div className="flex flex-wrap justify-between gap-2 py-3">
                  <dt className="text-muted-foreground">Registrado em</dt>
                  <dd>{fmtTime(finding.ts)}</dd>
                </div>
                <div className="flex flex-wrap justify-between gap-2 py-3">
                  <dt className="text-muted-foreground">Tarefa</dt>
                  <dd>
                    {finding.task_id ? (
                      <Link
                        href={`/function/tasks/detail?id=${encodeURIComponent(finding.task_id)}`}
                        className="inline-flex items-center gap-1 text-primary hover:underline"
                      >
                        #{finding.task_id} <ArrowRightIcon className="size-3" />
                      </Link>
                    ) : (
                      "—"
                    )}
                  </dd>
                </div>
              </dl>
              <p className="mt-3 text-xs text-muted-foreground">Ativos relacionados</p>
              <div className="mt-2 flex flex-wrap gap-1">
                {finding.assets?.length ? (
                  finding.assets.map((asset) => (
                    <code
                      key={asset.id}
                      className="max-w-full rounded-md border bg-background/70 px-2 py-1 font-mono text-xs break-all"
                    >
                      {asset.label}
                    </code>
                  ))
                ) : (
                  <span className="text-xs text-muted-foreground">Nenhum ativo associado.</span>
                )}
              </div>
            </section>
            {lineageLoaded && !hasLineage && (
              <div className="rounded-xl border border-dashed p-4 text-xs leading-5 text-muted-foreground">
                Sem trilha de exploração registrada para este achado. O grafo aparece quando há nós e relações reais.
              </div>
            )}
          </aside>
        </div>
      )}
    </main>
  );
}

export default function FindingDetailPage() {
  return (
    <React.Suspense fallback={null}>
      <FindingDetailInner />
    </React.Suspense>
  );
}
