"use client";

import * as React from "react";
import Link from "next/link";
import {
  ArrowRightIcon,
  ArrowUpRightIcon,
  CheckIcon,
  Clock3Icon,
  Loader2Icon,
  NetworkIcon,
  SearchIcon,
  ScanSearchIcon,
  ShieldCheckIcon,
  SlidersHorizontalIcon,
  SquareIcon,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api } from "@/lib/api";
import type { Task, VACampaign, VACapabilities, VACVECheck, VACVEIntel, VAPlan, VARun } from "@/lib/types";

const commonPorts = [
  21, 22, 25, 53, 80, 110, 135, 139, 143, 443, 445, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443,
];
type PortChoice = "common" | "first1000" | "all" | "custom";
const choices: Array<{ id: PortChoice; title: string; detail: string }> = [
  { id: "common", title: "Portas comuns", detail: "22, 80, 443 e outras 19" },
  { id: "first1000", title: "TCP 1–1000", detail: "Primeiras 1.000 portas" },
  { id: "all", title: "Todas as portas", detail: "1–65535 · até 62 IPs" },
  { id: "custom", title: "Personalizar", detail: "Lista ou intervalos" },
];
const statusLabels: Record<VARun["status"], string> = {
  running: "Em execução",
  completed: "Concluída",
  partial: "Parcial",
  failed: "Falhou",
  canceled: "Cancelada",
  interrupted: "Interrompida",
};

function parsePorts(raw: string): number[] {
  const ports = new Set<number>();
  for (const piece of raw.split(/[\s,;]+/).filter(Boolean)) {
    const match = /^(\d{1,5})(?:-(\d{1,5}))?$/.exec(piece);
    if (!match) throw new Error("Porta ou intervalo inválido: " + piece);
    const start = Number(match[1]);
    const end = Number(match[2] ?? match[1]);
    if (start < 1 || end > 65535 || end < start || end - start > 999) throw new Error("Intervalo inválido: " + piece);
    for (let port = start; port <= end; port++) ports.add(port);
    if (ports.size > 1000) throw new Error("A lista personalizada aceita até 1.000 portas TCP.");
  }
  if (!ports.size) throw new Error("Informe ao menos uma porta TCP.");
  return [...ports].sort((a, b) => a - b);
}

function initialExpiry() {
  const date = new Date(Date.now() + 2 * 60 * 60 * 1000);
  return new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
}

export default function VARunsPage() {
  const [intent, setIntent] = React.useState<"discovery" | "cve">("discovery");
  const [runs, setRuns] = React.useState<VARun[]>([]);
  const [cveRunID, setCVERunID] = React.useState("");
  const [cveID, setCVEID] = React.useState("");
  const [cveResult, setCVEResult] = React.useState<VACVECheck | null>(null);
  const [cveIntel, setCVEIntel] = React.useState<VACVEIntel | null>(null);
  const [cveBusy, setCVEBusy] = React.useState(false);
  const [tasks, setTasks] = React.useState<Task[]>([]);
  const [capabilities, setCapabilities] = React.useState<VACapabilities | null>(null);
  const [selected, setSelected] = React.useState<VARun | null>(null);
  const [taskID, setTaskID] = React.useState("");
  const [scopeTargets, setScopeTargets] = React.useState<string[]>([]);
  const [scopeLoading, setScopeLoading] = React.useState(false);
  const [scopeError, setScopeError] = React.useState("");
  const [portChoice, setPortChoice] = React.useState<PortChoice>("common");
  const [depth, setDepth] = React.useState<"standard" | "deep">("standard");
  const [customPorts, setCustomPorts] = React.useState("");
  const [approvedBy, setApprovedBy] = React.useState("");
  const [expires, setExpires] = React.useState("");
  const [plan, setPlan] = React.useState<VAPlan | null>(null);
  const [planSignature, setPlanSignature] = React.useState("");
  const [scopeConfirmed, setScopeConfirmed] = React.useState(false);
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState("");

  React.useEffect(() => {
    setExpires(initialExpiry());
    const params = new URLSearchParams(window.location.search);
    setTaskID(params.get("task") || "");
    if (params.get("depth") === "deep") setDepth("deep");
  }, []);
  React.useEffect(() => {
    let alive = true;
    void Promise.allSettled([api.tasks(), api.vaRuns(), api.vaCapabilities()]).then(
      ([taskResult, runResult, capsResult]) => {
        if (!alive) return;
        if (taskResult.status === "fulfilled") {
          setTasks(taskResult.value.tasks);
          if (taskResult.value.tasks.length === 1) setTaskID((current) => current || taskResult.value.tasks[0].id);
        }
        if (runResult.status === "fulfilled") {
          setRuns(runResult.value);
          const latest = runResult.value.find((run) => run.status === "completed" || run.status === "partial");
          if (latest) setCVERunID(latest.id);
          const active = runResult.value.find((run) => run.status === "running");
          if (active) setSelected(active);
          else if (latest)
            void api
              .vaRun(latest.id)
              .then((run) => {
                if (alive) setSelected(run);
              })
              .catch(() => undefined);
        }
        if (capsResult.status === "fulfilled") setCapabilities(capsResult.value);
        else setError("Não foi possível verificar o scanner desta instalação.");
      },
    );
    return () => {
      alive = false;
    };
  }, []);
  React.useEffect(() => {
    if (!selected || selected.status !== "running") return;
    const timer = window.setInterval(
      () =>
        void api
          .vaRun(selected.id)
          .then(setSelected)
          .catch(() => undefined),
      5000,
    );
    return () => window.clearInterval(timer);
  }, [selected?.id, selected?.status]);
  React.useEffect(() => {
    if (!selected || selected.status === "running") return;
    let active = true;
    void api
      .vaRuns()
      .then((latest) => {
        if (!active) return;
        setRuns(latest);
        if (selected.status === "completed" || selected.status === "partial") setCVERunID(selected.id);
      })
      .catch(() => undefined);
    return () => {
      active = false;
    };
  }, [selected?.id, selected?.status]);
  React.useEffect(() => {
    if (!taskID) {
      setScopeTargets([]);
      setScopeError("");
      return;
    }
    let active = true;
    setScopeLoading(true);
    setScopeTargets([]);
    setScopeError("");
    void Promise.all([api.taskInterceptRules(taskID), api.taskScope(taskID)])
      .then(([rules, scopeResult]) => {
        if (!active) return;
        const allowed = rules.filter(
          (rule) => rule.enabled && rule.action === "allow" && (rule.kind === "exact_ip" || rule.kind === "cidr"),
        );
        const hasExplicitIPRules = rules.some(
          (rule) => rule.action === "allow" && (rule.kind === "exact_ip" || rule.kind === "cidr"),
        );
        const legacy = hasExplicitIPRules
          ? []
          : scopeResult.scope
              .filter(
                (entry) =>
                  entry.task_id === Number(taskID) &&
                  entry.source === "manual" &&
                  (entry.kind === "ip" || entry.kind === "cidr"),
              )
              .map((entry) => (entry.kind === "ip" ? (entry.net || "").split("/")[0] : entry.net || ""));
        setScopeTargets([...new Set([...allowed.map((rule) => rule.pattern.trim()), ...legacy].filter(Boolean))]);
      })
      .catch((cause) => {
        if (active)
          setScopeError(cause instanceof Error ? cause.message : "Não foi possível carregar o escopo da tarefa.");
      })
      .finally(() => {
        if (active) setScopeLoading(false);
      });
    return () => {
      active = false;
    };
  }, [taskID]);
  function campaign(): VACampaign {
    const id = Number(taskID);
    if (!Number.isSafeInteger(id) || id <= 0) throw new Error("Selecione uma tarefa do SOC.");
    if (!approvedBy.trim()) throw new Error("Informe quem autorizou esta execução.");
    const expiry = new Date(expires);
    if (!Number.isFinite(expiry.getTime()) || expiry.getTime() <= Date.now())
      throw new Error("Escolha uma janela futura.");
    if (scopeLoading) throw new Error("Aguarde o escopo da tarefa carregar.");
    const targetList = scopeTargets;
    if (!targetList.length)
      throw new Error(
        "Esta tarefa não tem IPs ou CIDRs autorizados para VA. Cadastre uma tarefa com escopo antes de executar.",
      );
    const task = tasks.find((item) => item.id === taskID);
    const ports =
      portChoice === "all"
        ? []
        : portChoice === "first1000"
          ? Array.from({ length: 1000 }, (_, index) => index + 1)
          : portChoice === "common"
            ? commonPorts
            : parsePorts(customPorts);
    return {
      name: "VA · " + (task?.name || "Tarefa #" + id),
      task_id: id,
      approved_by: approvedBy.trim(),
      expires_at: expiry.toISOString(),
      targets: targetList,
      depth,
      port_profile: portChoice === "all" ? "all" : "custom",
      ports,
    };
  }
  function signature() {
    try {
      return JSON.stringify(campaign());
    } catch {
      return "";
    }
  }
  async function preview(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const input = campaign();
      const next = await api.vaPlan(input);
      setPlan(next);
      setPlanSignature(JSON.stringify(input));
      setScopeConfirmed(false);
    } catch (cause) {
      setPlan(null);
      setError(cause instanceof Error ? cause.message : "Não foi possível revisar a execução.");
    } finally {
      setBusy(false);
    }
  }
  async function start() {
    if (!plan || signature() !== planSignature || !scopeConfirmed || !capabilities?.scanner_available) return;
    setBusy(true);
    setError("");
    try {
      const started = await api.vaStart(campaign());
      setSelected(started);
      setRuns((current) => [started, ...current.filter((run) => run.id !== started.id)]);
      setPlan(null);
      setPlanSignature("");
      setScopeConfirmed(false);
      window.location.assign(`/chat?task=${encodeURIComponent(String(started.campaign.task_id))}&run=${encodeURIComponent(started.id)}`);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Não foi possível iniciar.");
    } finally {
      setBusy(false);
    }
  }
  async function stop() {
    if (!selected || selected.status !== "running") return;
    try {
      await api.vaCancel(selected.id);
      setSelected(await api.vaRun(selected.id));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Não foi possível interromper.");
    }
  }

  async function checkCVE(event: React.FormEvent) {
    event.preventDefault();
    setCVEBusy(true);
    setError("");
    setCVEResult(null);
    try {
      setCVEResult(await api.vaCheckCVE(cveRunID, cveID));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Não foi possível consultar a CVE.");
    } finally {
      setCVEBusy(false);
    }
  }

  async function lookupCVE(event: React.FormEvent) {
    event.preventDefault();
    setCVEBusy(true);
    setError("");
    setCVEIntel(null);
    setCVEResult(null);
    try {
      setCVEIntel(await api.vaLookupCVE(cveID));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Não foi possível consultar a CVE.");
    } finally {
      setCVEBusy(false);
    }
  }

  const selectedTask = tasks.find((task) => task.id === taskID);
  const portSummary =
    portChoice === "common"
      ? `${commonPorts.length} portas comuns`
      : portChoice === "first1000"
        ? "1.000 portas TCP"
        : portChoice === "all"
          ? "Todas as portas TCP"
          : customPorts.trim() || "Portas personalizadas";

  return (
    <div className="mx-auto max-w-7xl space-y-8 px-4 py-7 pb-20 sm:px-6 lg:px-10 lg:py-10">
      <header className="flex flex-col gap-5 border-b pb-7 sm:flex-row sm:items-end sm:justify-between">
        <div className="min-w-0">
          <p className="font-mono text-[11px] font-medium uppercase tracking-[0.2em] text-primary">
            SOC / AVALIAÇÃO DE INFRAESTRUTURA
          </p>
          <h1 className="mt-3 font-[family-name:var(--font-display)] text-4xl font-semibold tracking-tight sm:text-5xl">
            Nova execução
          </h1>
          <p className="mt-3 max-w-2xl text-sm leading-6 text-muted-foreground">
            Escolha a tarefa, ajuste o perfil e revise o escopo antes de iniciar.
          </p>
        </div>
        <div className="inline-flex w-fit items-center gap-2 rounded-full border border-border bg-card px-3 py-1.5 text-xs font-medium">
          <span
            className={`size-2 rounded-full ${capabilities?.scanner_available ? "bg-primary" : capabilities === null ? "bg-amber-400" : "bg-destructive"}`}
          />
          {capabilities === null
            ? "Verificando scanner"
            : capabilities.scanner_available
              ? "Scanner pronto"
              : "Scanner indisponível"}
        </div>
      </header>

      <nav aria-label="Modo de avaliação" className="flex gap-7 border-b">
        <button
          type="button"
          aria-pressed={intent === "discovery"}
          onClick={() => {
            setIntent("discovery");
            setError("");
          }}
          className={`inline-flex min-h-11 items-center gap-2 border-b-2 pb-3 text-sm font-medium transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary ${intent === "discovery" ? "border-primary text-foreground" : "border-transparent text-muted-foreground hover:text-foreground"}`}
        >
          <ScanSearchIcon className="size-4" /> Analisar infraestrutura
        </button>
        <button
          type="button"
          aria-pressed={intent === "cve"}
          onClick={() => {
            setIntent("cve");
            setError("");
          }}
          className={`inline-flex min-h-11 items-center gap-2 border-b-2 pb-3 text-sm font-medium transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary ${intent === "cve" ? "border-primary text-foreground" : "border-transparent text-muted-foreground hover:text-foreground"}`}
        >
          <SearchIcon className="size-4" /> Pesquisar CVE
        </button>
      </nav>

      {intent === "discovery" ? (
        <form className="grid items-start gap-8 xl:grid-cols-[minmax(0,1fr)_320px]" onSubmit={preview}>
          <div className="min-w-0 space-y-9">
            <section aria-labelledby="va-scope-heading" className="space-y-5">
              <div className="flex items-start gap-4">
                <span className="flex size-9 shrink-0 items-center justify-center rounded-md border border-primary/30 bg-primary/10 font-mono text-xs font-semibold text-primary">
                  01
                </span>
                <div>
                  <h2 id="va-scope-heading" className="text-lg font-semibold">
                    Tarefa e escopo
                  </h2>
                  <p className="mt-1 text-sm text-muted-foreground">Os alvos vêm da tarefa cadastrada no SOC.</p>
                </div>
              </div>
              <div className="space-y-3 pl-0 sm:pl-13">
                <div className="flex items-center justify-between gap-3">
                  <Label htmlFor="va-task">Tarefa do cliente</Label>
                  <Link
                    href="/function/tasks"
                    className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-primary"
                  >
                    Gerenciar tarefas <ArrowUpRightIcon className="size-3" />
                  </Link>
                </div>
                <select
                  id="va-task"
                  className="h-11 w-full rounded-md border border-input bg-card px-3 text-sm focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary"
                  value={taskID}
                  onChange={(event) => setTaskID(event.target.value)}
                >
                  <option value="">Selecione uma tarefa</option>
                  {tasks.map((task) => (
                    <option key={task.id} value={task.id}>
                      {task.name || task.description || "Tarefa #" + task.id} (#{task.id})
                    </option>
                  ))}
                </select>
                <div className="overflow-hidden rounded-lg border bg-card/50">
                  <div className="flex items-center justify-between gap-3 border-b px-4 py-3">
                    <div className="flex items-center gap-2 text-sm font-medium">
                      <NetworkIcon className="size-4 text-muted-foreground" /> IPs autorizados
                    </div>
                    <span className="font-mono text-xs text-muted-foreground">{scopeTargets.length} alvo(s)</span>
                  </div>
                  {scopeLoading ? (
                    <p role="status" className="px-4 py-5 text-sm text-muted-foreground">
                      Carregando escopo da tarefa…
                    </p>
                  ) : scopeTargets.length > 0 ? (
                    <div className="flex max-h-40 flex-wrap gap-2 overflow-auto p-4">
                      {scopeTargets.map((target) => (
                        <code
                          key={target}
                          className="rounded border bg-background px-2.5 py-1.5 text-xs text-foreground"
                        >
                          {target}
                        </code>
                      ))}
                    </div>
                  ) : (
                    <div className="space-y-2 px-4 py-5">
                      <p className="text-sm font-medium">Nenhum IP liberado para VA</p>
                      <p className="text-xs leading-5 text-muted-foreground">
                        {taskID
                          ? "Esta tarefa ainda não tem um escopo autorizado para execução."
                          : "Selecione uma tarefa para carregar os IPs autorizados."}
                      </p>
                      {taskID && (
                        <Link
                          href={`/function/tasks/detail?id=${encodeURIComponent(taskID)}`}
                          className="inline-flex items-center gap-1 text-xs font-medium text-primary hover:underline"
                        >
                          Abrir tarefa <ArrowRightIcon className="size-3" />
                        </Link>
                      )}
                    </div>
                  )}
                </div>
                {scopeError && (
                  <p role="alert" className="text-xs text-destructive">
                    {scopeError}
                  </p>
                )}
              </div>
            </section>

            <section aria-labelledby="va-profile-heading" className="space-y-5 border-t pt-8">
              <div className="flex items-start gap-4">
                <span className="flex size-9 shrink-0 items-center justify-center rounded-md border border-border bg-muted font-mono text-xs font-semibold text-muted-foreground">
                  02
                </span>
                <div>
                  <h2 id="va-profile-heading" className="text-lg font-semibold">
                    Perfil da análise
                  </h2>
                  <p className="mt-1 text-sm text-muted-foreground">Defina a cobertura de portas e a profundidade.</p>
                </div>
              </div>
              <div className="space-y-6 pl-0 sm:pl-13">
                <fieldset className="space-y-3">
                  <legend className="text-sm font-medium">Portas TCP</legend>
                  <div className="grid gap-2 sm:grid-cols-2">
                    {choices.map((choice) => (
                      <button
                        key={choice.id}
                        type="button"
                        onClick={() => setPortChoice(choice.id)}
                        aria-pressed={portChoice === choice.id}
                        className={`flex min-h-20 items-start justify-between gap-3 rounded-lg border px-4 py-3 text-left transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary ${portChoice === choice.id ? "border-primary/60 bg-primary/5" : "border-border bg-card/50 hover:border-primary/40"}`}
                      >
                        <span>
                          <span className="block text-sm font-medium">{choice.title}</span>
                          <span className="mt-1 block text-xs leading-5 text-muted-foreground">{choice.detail}</span>
                        </span>
                        {portChoice === choice.id && <CheckIcon className="mt-0.5 size-4 shrink-0 text-primary" />}
                      </button>
                    ))}
                  </div>
                  {portChoice === "custom" && (
                    <div className="space-y-2 pt-1">
                      <Label htmlFor="va-ports">Lista ou intervalos</Label>
                      <Input
                        id="va-ports"
                        value={customPorts}
                        onChange={(event) => setCustomPorts(event.target.value)}
                        className="font-mono"
                        placeholder="22,80,443 ou 1-1000"
                      />
                      <p className="text-xs text-muted-foreground">Até 1.000 portas TCP.</p>
                    </div>
                  )}
                </fieldset>
                <fieldset className="space-y-3">
                  <legend className="text-sm font-medium">Profundidade</legend>
                  <p className="text-xs leading-5 text-muted-foreground">
                    A execução começa com discovery. O VA aprofundado verifica apenas os serviços encontrados.
                  </p>
                  <div className="grid gap-2 sm:grid-cols-2">
                    <button
                      type="button"
                      aria-pressed={depth === "standard"}
                      onClick={() => setDepth("standard")}
                      className={`flex min-h-24 items-start justify-between gap-3 rounded-lg border p-4 text-left focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary ${depth === "standard" ? "border-primary/60 bg-primary/5" : "border-border bg-card/50 hover:border-primary/40"}`}
                    >
                      <span>
                        <strong className="block text-sm font-medium">Discovery</strong>
                        <span className="mt-1 block text-xs leading-5 text-muted-foreground">
                          Serviços e correlação NVD.
                        </span>
                      </span>
                      {depth === "standard" && <CheckIcon className="size-4 shrink-0 text-primary" />}
                    </button>
                    <button
                      type="button"
                      aria-pressed={depth === "deep"}
                      onClick={() => setDepth("deep")}
                      disabled={Boolean(capabilities?.vt_enabled && !capabilities?.vt_available)}
                      className={`flex min-h-24 items-start justify-between gap-3 rounded-lg border p-4 text-left focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary ${depth === "deep" ? "border-primary/60 bg-primary/5" : "border-border bg-card/50 hover:border-primary/40"}`}
                    >
                      <span>
                        <strong className="block text-sm font-medium">VA aprofundado</strong>
                        <span className="mt-1 block text-xs leading-5 text-muted-foreground">
                          {capabilities?.vt_enabled
                            ? capabilities.vt_available
                              ? "Até 16 IPs · TLS, SMB e verificações de vulnerabilidade."
                              : "Feed de vulnerabilidades em preparação."
                            : "Até 16 IPs · TLS e SMB read-only."}
                        </span>
                      </span>
                      {depth === "deep" && <CheckIcon className="size-4 shrink-0 text-primary" />}
                    </button>
                  </div>
                </fieldset>
              </div>
            </section>

            <section aria-labelledby="va-window-heading" className="space-y-5 border-t pt-8">
              <div className="flex items-start gap-4">
                <span className="flex size-9 shrink-0 items-center justify-center rounded-md border border-border bg-muted font-mono text-xs font-semibold text-muted-foreground">
                  03
                </span>
                <div>
                  <h2 id="va-window-heading" className="text-lg font-semibold">
                    Janela autorizada
                  </h2>
                  <p className="mt-1 text-sm text-muted-foreground">
                    Identifique o responsável e o prazo desta execução.
                  </p>
                </div>
              </div>
              <div className="space-y-5 pl-0 sm:pl-13">
                <div className="grid gap-4 sm:grid-cols-2">
                  <div className="space-y-2">
                    <Label htmlFor="va-approver">Autorizado por</Label>
                    <Input
                      id="va-approver"
                      value={approvedBy}
                      onChange={(event) => setApprovedBy(event.target.value)}
                      placeholder="Nome do responsável"
                      autoComplete="off"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="va-expiry">Fim da janela</Label>
                    <Input
                      id="va-expiry"
                      type="datetime-local"
                      value={expires}
                      onChange={(event) => setExpires(event.target.value)}
                    />
                  </div>
                </div>
                {capabilities?.scanner_available === false && (
                  <p role="status" className="text-sm text-muted-foreground">
                    O scanner está indisponível neste ambiente. A revisão do plano continua disponível.
                  </p>
                )}
                {error && (
                  <p
                    role="alert"
                    className="rounded-md border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive"
                  >
                    {error}
                  </p>
                )}
                <div className="flex flex-wrap items-center justify-between gap-3 border-t pt-5">
                  <p className="max-w-sm text-xs leading-5 text-muted-foreground">
                    A próxima etapa mostra todos os IPs e exige confirmação antes de gerar tráfego.
                  </p>
                  <Button type="submit" size="lg" disabled={busy || scopeLoading || scopeTargets.length === 0}>
                    {busy && <Loader2Icon className="size-4 animate-spin" />} Revisar plano{" "}
                    <ArrowRightIcon className="size-4" />
                  </Button>
                </div>
              </div>
            </section>
          </div>
          <aside className="hidden xl:sticky xl:top-7 xl:block">
            <div className="rounded-xl border bg-card p-5 shadow-sm">
              <div className="flex items-center gap-2">
                <SlidersHorizontalIcon className="size-4 text-primary" />
                <h2 className="text-sm font-semibold">Resumo da execução</h2>
              </div>
              <p className="mt-2 text-xs leading-5 text-muted-foreground">
                O plano será confirmado antes do início do scan.
              </p>
              <dl className="mt-5 divide-y text-sm">
                <div className="flex items-start justify-between gap-3 py-3">
                  <dt className="text-muted-foreground">Tarefa</dt>
                  <dd className="max-w-40 truncate text-right font-medium" title={selectedTask?.name}>
                    {selectedTask?.name || (taskID ? `#${taskID}` : "Não selecionada")}
                  </dd>
                </div>
                <div className="flex items-center justify-between gap-3 py-3">
                  <dt className="text-muted-foreground">Escopo</dt>
                  <dd className="font-mono font-medium">{scopeLoading ? "…" : `${scopeTargets.length} alvo(s)`}</dd>
                </div>
                <div className="flex items-start justify-between gap-3 py-3">
                  <dt className="text-muted-foreground">Portas</dt>
                  <dd className="max-w-40 text-right font-medium">{portSummary}</dd>
                </div>
                <div className="flex items-center justify-between gap-3 py-3">
                  <dt className="text-muted-foreground">Perfil</dt>
                  <dd className="font-medium">{depth === "deep" ? "Aprofundado" : "Discovery"}</dd>
                </div>
                <div className="flex items-center justify-between gap-3 py-3">
                  <dt className="inline-flex items-center gap-1.5 text-muted-foreground">
                    <Clock3Icon className="size-3.5" /> Até
                  </dt>
                  <dd className="font-medium">
                    {expires
                      ? new Date(expires).toLocaleString("pt-BR", { dateStyle: "short", timeStyle: "short" })
                      : "—"}
                  </dd>
                </div>
              </dl>
              <div
                className={`mt-5 flex items-start gap-2 rounded-md p-3 text-xs leading-5 ${scopeTargets.length > 0 ? "bg-primary/10 text-primary" : "bg-muted text-muted-foreground"}`}
              >
                <ShieldCheckIcon className="mt-0.5 size-4 shrink-0" />
                <span>
                  {scopeTargets.length > 0
                    ? "Escopo carregado. Revise o plano antes de iniciar."
                    : "Selecione uma tarefa com IPs autorizados para continuar."}
                </span>
              </div>
            </div>
          </aside>
        </form>
      ) : (
        <section className="max-w-4xl space-y-6" aria-labelledby="va-cve-heading">
          <div className="flex items-start gap-4">
            <span className="flex size-9 shrink-0 items-center justify-center rounded-md border border-primary/30 bg-primary/10 font-mono text-xs font-semibold text-primary">
              01
            </span>
            <div>
              <h2 id="va-cve-heading" className="text-lg font-semibold">
                Pesquisar CVE
              </h2>
              <p className="mt-1 text-sm text-muted-foreground">
                Consulte fontes públicas e compare com serviços observados em uma execução.
              </p>
            </div>
          </div>
          <div className="space-y-5 rounded-xl border bg-card p-5 md:p-7">
            <form onSubmit={lookupCVE} className="flex flex-col gap-3 sm:flex-row sm:items-end">
              <div className="flex-1 space-y-2">
                <Label htmlFor="cve-id">CVE</Label>
                <Input
                  id="cve-id"
                  value={cveID}
                  onChange={(event) => setCVEID(event.target.value.toUpperCase())}
                  placeholder="CVE-2024-6387"
                  autoComplete="off"
                />
              </div>
              <Button size="lg" disabled={cveBusy || !/^CVE-\d{4}-\d{4,}$/.test(cveID)}>
                {cveBusy ? "Consultando…" : "Buscar CVE"}
              </Button>
            </form>
            {error && (
              <p role="alert" className="text-sm text-destructive">
                {error}
              </p>
            )}
            {cveIntel && (
              <div className="space-y-4 border-t border-border pt-5 text-sm">
                <div className="flex flex-wrap items-center gap-2">
                  <strong>{cveIntel.cve}</strong>
                  {cveIntel.vuln_status && <Badge variant="outline">NVD: {cveIntel.vuln_status}</Badge>}
                  {cveIntel.source_status.local_scap === "ok" && <Badge variant="outline">Base CVE local</Badge>}
                  {cveIntel.kev && <Badge variant="destructive">Exploração observada · CISA KEV</Badge>}
                  {cveIntel.epss !== undefined && (
                    <Badge variant="outline">EPSS {(cveIntel.epss * 100).toFixed(1)}%</Badge>
                  )}
                </div>
                {cveIntel.description && <p>{cveIntel.description}</p>}
                <p className="text-xs text-muted-foreground">
                  {cveIntel.published && `Publicada: ${new Date(cveIntel.published).toLocaleDateString("pt-BR")} · `}
                  Fontes: {cveIntel.source_status.nvd === "ok" ? "NVD" : "NVD indisponível"}
                  {cveIntel.source_status.local_scap === "ok" ? `, base CVE local (${cveIntel.local_feed_count?.toLocaleString("pt-BR") ?? "?"} registros)` : ""}
                  {cveIntel.source_status.github === "ok" ? ", GitHub Advisory" : ""}
                  {cveIntel.source_status.epss === "ok" ? ", FIRST EPSS" : ""}
                  {cveIntel.source_status.kev === "ok" ? ", CISA KEV" : ""}. Fonte indisponível não significa ausência
                  de risco.
                </p>
                {cveIntel.source_status.nvd !== "ok" && <p className="text-xs text-amber-300">Registro da base local para consulta. A aplicabilidade ao ativo precisa de validação pela NVD ou por VT.</p>}
                <a href={cveIntel.nvd_url} target="_blank" rel="noreferrer" className="text-primary underline">
                  Registro NVD
                </a>
                {cveIntel.exploit_references.length > 0 && (
                  <div className="space-y-2">
                    <h3 className="font-medium">Referências públicas de exploit/PoC</h3>
                    <p className="text-xs text-muted-foreground">
                      Links marcados como Exploit na NVD; não são validados nem executados pelo Guard4US.
                    </p>
                    {cveIntel.exploit_references.map((ref) => (
                      <a
                        key={ref.url}
                        href={ref.url}
                        target="_blank"
                        rel="noreferrer"
                        className="block break-all text-xs text-primary underline"
                      >
                        {ref.source || new URL(ref.url).hostname} · {ref.url}
                      </a>
                    ))}
                  </div>
                )}
                {cveIntel.advisories.length > 0 && (
                  <div className="space-y-2">
                    <h3 className="font-medium">Advisories do GitHub</h3>
                    {cveIntel.advisories.map((ref) => (
                      <a
                        key={ref.url}
                        href={ref.url}
                        target="_blank"
                        rel="noreferrer"
                        className="block break-all text-xs text-primary underline"
                      >
                        {ref.source || "GHSA"} · {ref.url}
                      </a>
                    ))}
                  </div>
                )}
                {cveIntel.references.length > 0 && (
                  <details>
                    <summary className="cursor-pointer font-medium">
                      Outras referências ({cveIntel.references.length})
                    </summary>
                    <div className="mt-2 space-y-2">
                      {cveIntel.references.map((ref) => (
                        <a
                          key={ref.url}
                          href={ref.url}
                          target="_blank"
                          rel="noreferrer"
                          className="block break-all text-xs text-primary underline"
                        >
                          {ref.source || new URL(ref.url).hostname} · {ref.url}
                        </a>
                      ))}
                    </div>
                  </details>
                )}
                {runs.some((run) => run.status === "completed" || run.status === "partial") && (
                  <details className="rounded-lg border p-3">
                    <summary className="cursor-pointer font-medium">Comparar com uma execução VA</summary>
                    <form onSubmit={checkCVE} className="mt-3 flex flex-wrap gap-2">
                      <select
                        aria-label="Execução concluída"
                        value={cveRunID}
                        onChange={(event) => setCVERunID(event.target.value)}
                        className="h-10 min-w-56 flex-1 rounded-md border border-input bg-background px-3 text-sm"
                      >
                        <option value="">Selecione uma execução</option>
                        {runs
                          .filter((run) => run.status === "completed" || run.status === "partial")
                          .map((run) => (
                            <option key={run.id} value={run.id}>
                              {run.campaign.name} · {new Date(run.created_at).toLocaleDateString("pt-BR")}
                            </option>
                          ))}
                      </select>
                      <Button disabled={cveBusy || !cveRunID}>Comparar serviços</Button>
                    </form>
                  </details>
                )}
              </div>
            )}
            {cveResult && (
              <div className="space-y-3 border-t border-border pt-5">
                <div className="flex items-center gap-2">
                  <strong>{cveResult.cve}</strong>
                  <Badge variant="outline">
                    {cveResult.status === "possible"
                      ? "Possível aplicação"
                      : cveResult.status === "not_detected"
                        ? "Sem correspondência observada"
                        : "Inconclusivo"}
                  </Badge>
                </div>
                <p className="text-sm text-muted-foreground">{cveResult.note}</p>
                <div className="max-h-64 space-y-2 overflow-auto">
                  {cveResult.matches.map((match, index) => (
                    <div key={index} className="rounded-md border p-3 text-xs">
                      <span className="font-mono">
                        {match.target}:{match.port}
                      </span>{" "}
                      · {match.service} {match.version} ·{" "}
                      {match.status === "possible"
                        ? "Possível"
                        : match.status === "not_detected"
                          ? "Sem correspondência"
                          : "Inconclusivo"}
                    </div>
                  ))}
                </div>
                {cveResult.exploit_references?.length ? (
                  <p className="text-xs text-muted-foreground">
                    A NVD indexa {cveResult.exploit_references.length} referência(s) pública(s) de exploit para esta
                    CVE. Consulte a busca de CVE acima; a correspondência não valida o PoC no ativo.
                  </p>
                ) : null}
                <a href={cveResult.source} target="_blank" rel="noreferrer" className="text-xs text-primary underline">
                  Abrir registro NVD
                </a>
              </div>
            )}
          </div>
        </section>
      )}

      {selected && (
        <Card>
          <CardContent className="space-y-4 p-5">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <p className="font-semibold">{selected.campaign.name}</p>
                <p className="mt-1 text-xs text-muted-foreground">
                  {selected.completed_hosts + selected.failed_hosts}/{selected.total_hosts} IPs ·{" "}
                  {selected.candidate_count} candidatos
                </p>
              </div>
              <Badge variant="outline">
                {selected.phase === "cve_review" ? "Correlacionando CVEs" : statusLabels[selected.status]}
              </Badge>
            </div>
            {selected.error && (
              <p role="alert" className="text-sm text-destructive">
                {selected.error}
              </p>
            )}
            {selected.cve_auto && (
              <div className="space-y-2 rounded-lg border p-4 text-sm">
                <div className="flex flex-wrap items-center gap-2">
                  <strong>CVEs correlacionadas automaticamente</strong>
                  <Badge variant="outline">
                    {selected.cve_auto.status === "completed"
                      ? "Consulta concluída"
                      : selected.cve_auto.status === "partial"
                        ? "Cobertura parcial"
                        : selected.cve_auto.status === "unavailable"
                          ? "Fonte indisponível"
                          : "Sem CPE preciso"}
                  </Badge>
                </div>
                <p className="text-xs text-muted-foreground">
                  {selected.cve_auto.cpes_checked} CPEs consultados · {selected.cve_auto.cves_checked} CVEs avaliadas ·{" "}
                  {selected.cve_auto.candidates} correspondências pendentes
                </p>
                <p className="text-xs text-muted-foreground">{selected.cve_auto.coverage_note}</p>
                {(selected.cve_checks || [])
                  .filter((check) => check.automatic && check.status === "possible")
                  .slice(0, 12)
                  .map((check) => (
                    <a
                      key={check.cve}
                      href={check.source}
                      target="_blank"
                      rel="noreferrer"
                      className="block text-xs text-primary underline"
                    >
                      {check.cve} · possível aplicação · revisar em Achados
                    </a>
                  ))}
                <p className="text-xs text-muted-foreground">
                  Correspondência de CPE e versão não confirma vulnerabilidade ou impacto. O SOC deve validar a CVE e a
                  situação de patch do ativo.
                </p>
              </div>
            )}
            {selected.result?.hosts?.length ? (
              <details className="text-sm">
                <summary className="cursor-pointer">Ver resultados por IP</summary>
                <div className="mt-3 max-h-80 overflow-auto rounded-lg border border-border">
                  {selected.result.hosts.map((host) => (
                    <div key={host.target} className="space-y-2 border-b border-border px-3 py-2 last:border-0">
                      <div className="flex items-center justify-between gap-3">
                        <span className="font-mono text-xs">{host.target}</span>
                        <span className="text-xs text-muted-foreground">
                          {host.error ||
                            `${host.services?.length ?? 0} serviço(s) · ${host.candidates.length} candidato(s)`}
                        </span>
                      </div>
                      {host.services?.map((service) => (
                        <p key={`${service.Port}/${service.Proto}`} className="font-mono text-xs text-muted-foreground">
                          {service.Port}/tcp · {service.Service || "desconhecido"}
                          {service.Product ? ` · ${service.Product}` : ""}
                          {service.Version ? ` ${service.Version}` : ""}
                        </p>
                      ))}
                      {host.deep_error && (
                        <p className="text-xs text-amber-600">VA aprofundado parcial: {host.deep_error}</p>
                      )}
                      {host.deep_checks?.map((check) => (
                        <p key={check.port + check.script} className="text-xs text-muted-foreground">
                          {check.port}/tcp · {check.script}: {check.output.slice(0, 180)}
                        </p>
                      ))}
                    </div>
                  ))}
                </div>
              </details>
            ) : null}
            <div className="flex flex-wrap gap-2">
              {selected.status === "running" && (
                <Button variant="outline" size="sm" onClick={() => void stop()}>
                  <SquareIcon className="size-3" /> Interromper
                </Button>
              )}
              <Button variant="outline" size="sm" asChild>
                <Link href={"/function/tasks/detail?id=" + selected.campaign.task_id}>
                  Abrir tarefa <ArrowRightIcon className="size-4" />
                </Link>
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {runs.length > 0 && (
        <Card>
          <CardContent className="space-y-3 p-5">
            <h2 className="text-sm font-semibold">Execuções recentes</h2>
            <div className="divide-y rounded-lg border">
              {runs.slice(0, 10).map((run) => (
                <button
                  key={run.id}
                  type="button"
                  className="flex w-full items-center justify-between gap-3 px-3 py-2 text-left text-sm hover:bg-muted/40"
                  onClick={() =>
                    void api
                      .vaRun(run.id)
                      .then(setSelected)
                      .catch((cause) =>
                        setError(cause instanceof Error ? cause.message : "Não foi possível abrir a execução."),
                      )
                  }
                >
                  <span className="min-w-0">
                    <span className="block truncate font-medium">{run.campaign.name}</span>
                    <span className="block text-xs text-muted-foreground">
                      {new Date(run.created_at).toLocaleString("pt-BR")} · {run.completed_hosts + run.failed_hosts}/
                      {run.total_hosts} IPs
                    </span>
                  </span>
                  <Badge variant="outline">
                    {run.phase === "cve_review" ? "Correlacionando CVEs" : statusLabels[run.status]}
                  </Badge>
                </button>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      <Dialog
        open={plan !== null}
        onOpenChange={(open) => {
          if (!open) {
            setPlan(null);
            setScopeConfirmed(false);
          }
        }}
      >
        <DialogContent className="sm:max-w-xl">
          <DialogHeader>
            <DialogTitle>Revisar e iniciar</DialogTitle>
            <DialogDescription>Confira o alcance exato antes de gerar tráfego.</DialogDescription>
          </DialogHeader>
          {plan && (
            <div className="space-y-4 text-sm">
              <div className="flex flex-wrap gap-2">
                <Badge variant="outline">{plan.targets.length} IPs</Badge>
                <Badge variant="outline">{plan.port_count.toLocaleString("pt-BR")} portas TCP</Badge>
                <Badge variant="outline">{plan.depth === "deep" ? "VA aprofundado" : "Discovery"}</Badge>
                <Badge variant="outline">Até {new Date(plan.expires_at).toLocaleString("pt-BR")}</Badge>
              </div>
              <details className="rounded-lg border border-border p-3" open>
                <summary className="cursor-pointer font-medium">IPs incluídos</summary>
                <div className="mt-3 max-h-48 overflow-auto font-mono text-xs text-muted-foreground">
                  {plan.targets.map((target) => (
                    <div key={target}>{target}</div>
                  ))}
                </div>
              </details>
              <label className="flex cursor-pointer items-start gap-3 rounded-lg border border-border p-3">
                <input
                  type="checkbox"
                  className="mt-1 accent-primary"
                  checked={scopeConfirmed}
                  onChange={(event) => setScopeConfirmed(event.target.checked)}
                />
                <span>Confirmei autorização, janela e origem de rede para todos esses IPs.</span>
              </label>
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setPlan(null)}>
              Voltar
            </Button>
            <Button disabled={!scopeConfirmed || busy || !capabilities?.scanner_available} onClick={() => void start()}>
              {busy && <Loader2Icon className="size-4 animate-spin" />} Iniciar análise
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
