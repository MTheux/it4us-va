"use client";

import * as React from "react";

import Link from "next/link";

import {
  ArrowLeftIcon,
  ArrowRightIcon,
  ClipboardListIcon,
  MessageSquareIcon,
  NetworkIcon,
  RadarIcon,
  ShieldCheckIcon,
} from "lucide-react";

import { StatusBadge } from "@/components/status-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import type { Asset, AssetInterceptRule, Finding, Task, VARun } from "@/lib/types";

const RUN_STATUS: Record<VARun["status"], string> = {
  running: "Em execução",
  completed: "Concluída",
  partial: "Parcial",
  failed: "Falhou",
  canceled: "Cancelada",
  interrupted: "Interrompida",
};

export function isDemoVATask(task: Task) {
  return task.description.startsWith("Ambiente ficticio para visualizar ativos e achados.");
}

function timeLabel(value?: string) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString("pt-BR", { dateStyle: "short", timeStyle: "short" });
}

export function VADetail({ task }: { task: Task }) {
  const demo = isDemoVATask(task);
  const [runs, setRuns] = React.useState<VARun[]>([]);
  const [rules, setRules] = React.useState<AssetInterceptRule[]>([]);
  const [assets, setAssets] = React.useState<Asset[]>([]);
  const [findings, setFindings] = React.useState<Finding[]>([]);
  const [loaded, setLoaded] = React.useState(false);

  React.useEffect(() => {
    let alive = true;
    async function refresh() {
      const [runResult, ruleResult, assetResult, findingResult] = await Promise.allSettled([
        api.vaRuns(),
        api.taskInterceptRules(task.id),
        api.taskAssets(task.id, "ip", 50, 0),
        api.findings(task.id),
      ]);
      if (!alive) return;
      if (runResult.status === "fulfilled")
        setRuns(runResult.value.filter((run) => String(run.campaign.task_id) === task.id));
      if (ruleResult.status === "fulfilled") setRules(ruleResult.value);
      if (assetResult.status === "fulfilled") setAssets(assetResult.value.assets);
      if (findingResult.status === "fulfilled")
        setFindings(findingResult.value.filter((finding) => String(finding.task_id) === task.id || finding.inherited));
      setLoaded(true);
    }
    void refresh();
    const timer = window.setInterval(() => void refresh(), 5000);
    return () => {
      alive = false;
      window.clearInterval(timer);
    };
  }, [task.id]);

  const latest = runs[0];
  const allow = rules.filter(
    (rule) => rule.enabled && rule.action === "allow" && (rule.kind === "exact_ip" || rule.kind === "cidr"),
  );
  const observedIPs = [...new Set(assets.map((asset) => asset.ip).filter((ip): ip is string => !!ip))];
  const canRun = !demo && allow.length > 0;
  const candidates = findings.length;
  let taskBadge: "default" | "secondary" | "outline" = "outline";
  let taskBadgeLabel = "Pronta para VA";
  if (demo) {
    taskBadge = "secondary";
    taskBadgeLabel = "Dados fictícios";
  } else if (latest) {
    taskBadgeLabel = RUN_STATUS[latest.status];
    if (latest.status === "running") taskBadge = "default";
  }
  let emptyRunText = "Crie uma tarefa com IPs autorizados para iniciar uma campanha.";
  if (demo) emptyRunText = "Os achados abaixo são exemplos para avaliar a interface.";
  else if (canRun) emptyRunText = "Revise as portas e inicie a primeira campanha para esta tarefa.";
  let emptyFindingText = "Nenhum achado registrado nesta tarefa.";
  if (latest?.candidate_count)
    emptyFindingText = `O scanner registrou ${latest.candidate_count} candidato(s) na execução recente; nenhum achado foi registrado para triagem aqui. Revise o recibo da VA.`;

  return (
    <main data-content-padding="false" className="mx-auto w-full max-w-7xl space-y-6 px-4 py-6 lg:px-10">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <Button asChild variant="ghost" size="sm" className="-ml-2">
          <Link href="/function/tasks">
            <ArrowLeftIcon /> Tarefas
          </Link>
        </Button>
        <span className="font-mono text-xs text-muted-foreground">#{task.id}</span>
      </div>

      <header className="flex flex-wrap items-end justify-between gap-4 border-b pb-6">
        <div className="min-w-0">
          <p className="font-mono text-[11px] font-medium uppercase tracking-[0.2em] text-primary">SOC / TAREFA VA</p>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <h1 className="min-w-0 font-[family-name:var(--font-display)] text-3xl font-semibold tracking-tight sm:text-4xl">
              {task.name ?? `Tarefa #${task.id}`}
            </h1>
            <Badge variant={taskBadge}>{taskBadgeLabel}</Badge>
          </div>
          <p className="mt-2 max-w-2xl text-sm text-muted-foreground">
            {demo
              ? "Ambiente de demonstração para visualizar inventário e achados. Nenhum scan real foi executado."
              : "Escopo autorizado, execuções de infraestrutura e candidatos para triagem em um só lugar."}
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          {!demo && (
            <Button asChild size="sm" variant="outline">
              <Link href={`/chat?task=${encodeURIComponent(task.id)}`}>
                <MessageSquareIcon /> Chat VA
              </Link>
            </Button>
          )}
          {canRun && (
            <Button asChild size="sm">
              <Link href={`/function/va-runs?task=${encodeURIComponent(task.id)}`}>
                <RadarIcon /> Nova execução VA
              </Link>
            </Button>
          )}
          {demo && (
            <Button asChild size="sm">
              <Link href="/function/tasks">
                <ArrowRightIcon /> Ver tarefas
              </Link>
            </Button>
          )}
        </div>
      </header>

      <section className="grid gap-3 sm:grid-cols-3" aria-label="Resumo da tarefa">
        <div className="rounded-xl border bg-card/50 p-4">
          <p className="text-xs text-muted-foreground">{demo ? "IPs de demonstração" : "IPs e ranges autorizados"}</p>
          <p className="mt-1 text-2xl font-semibold tabular-nums">{demo ? observedIPs.length : allow.length}</p>
        </div>
        <div className="rounded-xl border bg-card/50 p-4">
          <p className="text-xs text-muted-foreground">Execuções VA recentes</p>
          <p className="mt-1 text-2xl font-semibold tabular-nums">{runs.length}</p>
        </div>
        <div className="rounded-xl border bg-card/50 p-4">
          <p className="text-xs text-muted-foreground">{demo ? "Achados fictícios" : "Achados registrados"}</p>
          <p className="mt-1 text-2xl font-semibold tabular-nums">{candidates}</p>
        </div>
      </section>

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1.35fr)_minmax(18rem,0.85fr)]">
        <section className="min-w-0 rounded-xl border bg-card/50" aria-labelledby="runs-heading">
          <div className="flex items-center justify-between gap-3 border-b px-4 py-4">
            <div>
              <p className="font-mono text-[10px] uppercase tracking-widest text-primary">EXECUÇÃO</p>
              <h2 id="runs-heading" className="mt-1 text-lg font-semibold">
                Histórico VA
              </h2>
            </div>
            <RadarIcon className="size-5 text-primary" />
          </div>
          {runs.length ? (
            <div className="divide-y">
              {runs.slice(0, 5).map((run) => (
                <div key={run.id} className="flex flex-wrap items-center justify-between gap-3 px-4 py-4">
                  <div>
                    <p className="text-sm font-medium">
                      {run.campaign.depth === "deep" ? "Discovery + VA aprofundado" : "Discovery"}
                    </p>
                    <p className="mt-1 text-xs text-muted-foreground">
                      {timeLabel(run.created_at)} · {run.completed_hosts + run.failed_hosts}/{run.total_hosts} hosts ·{" "}
                      {run.candidate_count} candidato(s)
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant={run.status === "running" ? "default" : "secondary"}>{RUN_STATUS[run.status]}</Badge>
                    <Button asChild size="sm" variant="ghost">
                      <Link href={`/chat?task=${encodeURIComponent(task.id)}&run=${encodeURIComponent(run.id)}`}>
                        Acompanhar <ArrowRightIcon />
                      </Link>
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="px-4 py-8">
              <p className="text-sm font-medium">{demo ? "Demonstração sem execução" : "Nenhuma VA recente"}</p>
              <p className="mt-1 text-sm text-muted-foreground">{emptyRunText}</p>
              {canRun && (
                <Button asChild size="sm" variant="outline" className="mt-4">
                  <Link href={`/function/va-runs?task=${encodeURIComponent(task.id)}`}>
                    Planejar execução <ArrowRightIcon />
                  </Link>
                </Button>
              )}
            </div>
          )}
        </section>

        <section className="min-w-0 rounded-xl border bg-card/50" aria-labelledby="scope-heading">
          <div className="flex items-center justify-between gap-3 border-b px-4 py-4">
            <div>
              <p className="font-mono text-[10px] uppercase tracking-widest text-primary">ALVOS</p>
              <h2 id="scope-heading" className="mt-1 text-lg font-semibold">
                {demo ? "Inventário fictício" : "Escopo autorizado"}
              </h2>
            </div>
            <NetworkIcon className="size-5 text-primary" />
          </div>
          <div className="space-y-2 p-4">
            {(demo ? observedIPs : allow.map((rule) => rule.pattern)).slice(0, 20).map((value) => (
              <div key={value} className="rounded-lg border bg-background/70 px-3 py-2 font-mono text-xs break-all">
                {value}
              </div>
            ))}
            {!demo && allow.length > 20 && (
              <p className="text-xs text-muted-foreground">Mais {allow.length - 20} entradas autorizadas.</p>
            )}
            {demo && observedIPs.length > 20 && (
              <p className="text-xs text-muted-foreground">Mais {observedIPs.length - 20} IPs fictícios.</p>
            )}
            {loaded && (demo ? observedIPs.length === 0 : allow.length === 0) && (
              <p className="text-sm text-muted-foreground">
                {demo ? "Nenhum IP fictício associado." : "Nenhum IP ou CIDR autorizado nesta tarefa."}
              </p>
            )}
            {!loaded && <p className="text-sm text-muted-foreground">Carregando escopo…</p>}
          </div>
          <div className="border-t px-4 py-3 text-xs text-muted-foreground">
            {demo
              ? "IPs RFC 5737 usados apenas para demonstração."
              : "A execução VA usa somente os IPs e ranges permitidos nesta tarefa."}
          </div>
        </section>
      </div>

      <section className="overflow-hidden rounded-xl border bg-card/50" aria-labelledby="findings-heading">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b px-4 py-4">
          <div>
            <p className="font-mono text-[10px] uppercase tracking-widest text-primary">TRIAGEM</p>
            <h2 id="findings-heading" className="mt-1 text-lg font-semibold">
              {demo ? "Achados de exemplo" : "Candidatos e achados"}
            </h2>
          </div>
          <ClipboardListIcon className="size-5 text-primary" />
        </div>
        {findings.length ? (
          <div className="divide-y">
            {findings.slice(0, 8).map((finding) => (
              <div key={finding.id} className="flex flex-wrap items-start justify-between gap-3 px-4 py-3">
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <StatusBadge domain="severity" value={finding.severity} dot />
                    <p className="text-sm font-medium">{finding.name || finding.vulnclass || "Achado sem título"}</p>
                  </div>
                  <p className="mt-1 line-clamp-2 text-xs leading-5 text-muted-foreground">{finding.summary}</p>
                </div>
                {finding.finding_id && (
                  <Button asChild size="sm" variant="ghost">
                    <Link href={`/function/findings/detail?id=${encodeURIComponent(finding.finding_id)}`}>
                      Detalhes <ArrowRightIcon />
                    </Link>
                  </Button>
                )}
              </div>
            ))}
          </div>
        ) : (
          <div className="px-4 py-8 text-sm text-muted-foreground">
            {loaded ? emptyFindingText : "Carregando achados…"}
          </div>
        )}
        {findings.length > 8 && (
          <p className="border-t px-4 py-3 text-xs text-muted-foreground">
            Exibindo os 8 achados mais recentes desta tarefa.
          </p>
        )}
      </section>

      <div className="flex items-center gap-2 rounded-xl border border-primary/20 bg-primary/5 p-4 text-xs text-muted-foreground">
        <ShieldCheckIcon className="size-4 shrink-0 text-primary" />
        <p>
          {demo
            ? "Esta tarefa apresenta dados sintéticos e não autoriza varreduras."
            : "Um novo VA só começa após revisar escopo, portas e plano em Execuções VA."}
        </p>
      </div>
    </main>
  );
}
