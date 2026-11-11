"use client";

import * as React from "react";
import Link from "next/link";
import { ArrowRightIcon, CheckCircle2Icon, Loader2Icon, ScanSearchIcon, SquareIcon } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { Task, VACampaign, VACapabilities, VAPlan, VARun } from "@/lib/types";

const commonPorts = [21, 22, 25, 53, 80, 110, 135, 139, 143, 443, 445, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443];
type PortChoice = "common" | "first1000" | "all" | "custom";
const choices: Array<{ id: PortChoice; title: string; detail: string }> = [
  { id: "common", title: "Portas comuns", detail: "22, 80, 443 e outras 19" },
  { id: "first1000", title: "TCP 1–1000", detail: "Primeiras 1.000 portas" },
  { id: "all", title: "Todas as portas", detail: "1–65535 · até 62 IPs" },
  { id: "custom", title: "Personalizar", detail: "Lista ou intervalos" },
];
const statusLabels: Record<VARun["status"], string> = {
  running: "Em execução", completed: "Concluída", partial: "Parcial",
  failed: "Falhou", canceled: "Cancelada", interrupted: "Interrompida",
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
  const [tasks, setTasks] = React.useState<Task[]>([]);
  const [capabilities, setCapabilities] = React.useState<VACapabilities | null>(null);
  const [selected, setSelected] = React.useState<VARun | null>(null);
  const [taskID, setTaskID] = React.useState("");
  const [targets, setTargets] = React.useState("");
  const [portChoice, setPortChoice] = React.useState<PortChoice>("common");
  const [customPorts, setCustomPorts] = React.useState("");
  const [approvedBy, setApprovedBy] = React.useState("");
  const [expires, setExpires] = React.useState("");
  const [name, setName] = React.useState("");
  const [plan, setPlan] = React.useState<VAPlan | null>(null);
  const [planSignature, setPlanSignature] = React.useState("");
  const [scopeConfirmed, setScopeConfirmed] = React.useState(false);
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState("");

  React.useEffect(() => { setExpires(initialExpiry()); }, []);
  React.useEffect(() => {
    let alive = true;
    void Promise.allSettled([api.tasks(), api.vaRuns(), api.vaCapabilities()]).then(([taskResult, runResult, capsResult]) => {
      if (!alive) return;
      if (taskResult.status === "fulfilled") {
        setTasks(taskResult.value.tasks);
        if (taskResult.value.tasks.length === 1) setTaskID(taskResult.value.tasks[0].id);
      }
      if (runResult.status === "fulfilled") {
        const active = runResult.value.find((run) => run.status === "running");
        if (active) setSelected(active);
      }
      if (capsResult.status === "fulfilled") setCapabilities(capsResult.value);
      else setError("Não foi possível verificar o scanner desta instalação.");
    });
    return () => { alive = false; };
  }, []);
  React.useEffect(() => {
    if (!selected || selected.status !== "running") return;
    const timer = window.setInterval(() => void api.vaRun(selected.id).then(setSelected).catch(() => undefined), 5000);
    return () => window.clearInterval(timer);
  }, [selected?.id, selected?.status]);

  function campaign(): VACampaign {
    const id = Number(taskID);
    if (!Number.isSafeInteger(id) || id <= 0) throw new Error("Selecione uma tarefa do SOC.");
    if (!approvedBy.trim()) throw new Error("Informe quem autorizou esta execução.");
    const expiry = new Date(expires);
    if (!Number.isFinite(expiry.getTime()) || expiry.getTime() <= Date.now()) throw new Error("Escolha uma janela futura.");
    const targetList = targets.split(/[\s,;]+/).filter(Boolean);
    if (!targetList.length) throw new Error("Informe os IPs ou ranges CIDR autorizados.");
    const task = tasks.find((item) => item.id === taskID);
    const ports = portChoice === "all" ? [] : portChoice === "first1000"
      ? Array.from({ length: 1000 }, (_, index) => index + 1)
      : portChoice === "common" ? commonPorts : parsePorts(customPorts);
    return {
      name: name.trim() || "VA · " + (task?.name || "Tarefa #" + id),
      task_id: id, approved_by: approvedBy.trim(), expires_at: expiry.toISOString(),
      targets: targetList, port_profile: portChoice === "all" ? "all" : "custom", ports,
    };
  }
  function signature() {
    try { return JSON.stringify(campaign()); } catch { return ""; }
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
    } finally { setBusy(false); }
  }
  async function start() {
    if (!plan || signature() !== planSignature || !scopeConfirmed || !capabilities?.scanner_available) return;
    setBusy(true);
    setError("");
    try {
      setSelected(await api.vaStart(campaign()));
      setPlan(null);
      setPlanSignature("");
      setScopeConfirmed(false);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Não foi possível iniciar.");
    } finally { setBusy(false); }
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

  return (
    <div className="mx-auto max-w-4xl space-y-7 p-6 pb-16 md:p-10">
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="font-mono text-xs font-medium uppercase tracking-[0.18em] text-primary">SOC / IT4US VA</p>
          <h1 className="mt-2 flex items-center gap-3 text-3xl font-semibold tracking-tight"><ScanSearchIcon className="size-7 text-primary" /> Nova execução</h1>
          <p className="mt-2 text-sm text-muted-foreground">Defina os alvos e as portas. Revise antes de iniciar.</p>
        </div>
        <Badge variant="outline" className={capabilities?.scanner_available ? "border-primary/40 text-primary" : ""}>
          {capabilities === null ? "Verificando scanner" : capabilities.scanner_available ? "Scanner pronto" : "Scanner indisponível"}
        </Badge>
      </header>

      <Card><CardContent className="p-5 md:p-7">
        <form className="space-y-7" onSubmit={preview}>
          <div className="space-y-2">
            <Label htmlFor="va-task">Tarefa do cliente</Label>
            <select id="va-task" className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm focus-visible:outline-2 focus-visible:outline-primary" value={taskID} onChange={(event) => setTaskID(event.target.value)}>
              <option value="">Selecione a tarefa</option>
              {tasks.map((task) => <option key={task.id} value={task.id}>{task.name || task.description || "Tarefa #" + task.id} (#{task.id})</option>)}
            </select>
            {tasks.length === 0 && <Link href="/function/tasks" className="inline-flex items-center gap-1 text-xs text-primary hover:underline">Criar tarefa para este cliente <ArrowRightIcon className="size-3" /></Link>}
          </div>
          <div className="space-y-2">
            <Label htmlFor="va-targets">IPs e ranges autorizados</Label>
            <Textarea id="va-targets" value={targets} onChange={(event) => setTargets(event.target.value)} rows={4} className="font-mono" spellCheck={false} placeholder={"192.0.2.10\n198.51.100.0/28"} />
            <p className="text-xs text-muted-foreground">Um IP ou CIDR por linha. Até 4.096 IPs; sem hostnames.</p>
          </div>
          <fieldset className="space-y-3">
            <legend className="text-sm font-medium">O que deseja fazer?</legend>
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="rounded-lg border border-primary/50 bg-primary/5 p-4">
                <div className="flex items-center justify-between gap-2"><span className="font-medium">Descobrir serviços</span><CheckCircle2Icon className="size-4 text-primary" /></div>
                <p className="mt-1 text-xs text-muted-foreground">Portas TCP e serviços para revisão do SOC.</p>
              </div>
              <div aria-disabled="true" className="rounded-lg border border-border bg-muted/30 p-4 opacity-65">
                <div className="flex items-center justify-between gap-2"><span className="font-medium">Verificar CVE específica</span><Badge variant="outline" className="text-[10px]">Em preparação</Badge></div>
                <p className="mt-1 text-xs text-muted-foreground">Ainda não há executor de CVE nesta instalação.</p>
              </div>
            </div>
          </fieldset>
          <fieldset className="space-y-3">
            <legend className="text-sm font-medium">Portas TCP</legend>
            <div className="grid gap-2 sm:grid-cols-2">
              {choices.map((choice) => <button key={choice.id} type="button" onClick={() => setPortChoice(choice.id)} aria-pressed={portChoice === choice.id} className={"rounded-lg border px-4 py-3 text-left transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary " + (portChoice === choice.id ? "border-primary bg-primary/5" : "border-border hover:border-primary/40")}>
                <span className="block text-sm font-medium">{choice.title}</span><span className="mt-1 block text-xs text-muted-foreground">{choice.detail}</span>
              </button>)}
            </div>
            {portChoice === "custom" && <div className="space-y-2"><Label htmlFor="va-ports">Lista de portas</Label><Input id="va-ports" value={customPorts} onChange={(event) => setCustomPorts(event.target.value)} className="font-mono" placeholder="22,80,443 ou 1-1000" /><p className="text-xs text-muted-foreground">Até 1.000 portas personalizadas.</p></div>}
          </fieldset>
          <div className="grid gap-4 border-t border-border pt-6 sm:grid-cols-2">
            <div className="space-y-2"><Label htmlFor="va-approver">Autorizado por</Label><Input id="va-approver" value={approvedBy} onChange={(event) => setApprovedBy(event.target.value)} placeholder="Nome do responsável" /></div>
            <div className="space-y-2"><Label htmlFor="va-expiry">Fim da janela autorizada</Label><Input id="va-expiry" type="datetime-local" value={expires} onChange={(event) => setExpires(event.target.value)} /></div>
          </div>
          <details className="text-sm"><summary className="cursor-pointer text-muted-foreground hover:text-foreground">Nome da execução (opcional)</summary><div className="mt-3"><Label htmlFor="va-name">Nome</Label><Input id="va-name" className="mt-2" value={name} onChange={(event) => setName(event.target.value)} placeholder="Usar nome da tarefa" /></div></details>
          {capabilities?.scanner_available === false && <p role="status" className="text-sm text-muted-foreground">O scanner não está instalado neste ambiente. A revisão do escopo continua disponível.</p>}
          {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
          <div className="flex justify-end"><Button type="submit" disabled={busy}>{busy && <Loader2Icon className="size-4 animate-spin" />} Revisar execução <ArrowRightIcon className="size-4" /></Button></div>
        </form>
      </CardContent></Card>

      {selected && <Card><CardContent className="space-y-4 p-5">
        <div className="flex flex-wrap items-center justify-between gap-3"><div><p className="font-semibold">{selected.campaign.name}</p><p className="mt-1 text-xs text-muted-foreground">{selected.completed_hosts + selected.failed_hosts}/{selected.total_hosts} IPs · {selected.candidate_count} candidatos</p></div><Badge variant="outline">{statusLabels[selected.status]}</Badge></div>
        {selected.error && <p role="alert" className="text-sm text-destructive">{selected.error}</p>}
        {selected.result?.hosts?.length ? <details className="text-sm"><summary className="cursor-pointer">Ver resultados por IP</summary><div className="mt-3 max-h-64 overflow-auto rounded-lg border border-border">{selected.result.hosts.map((host) => <div key={host.target} className="flex items-center justify-between gap-3 border-b border-border px-3 py-2 last:border-0"><span className="font-mono text-xs">{host.target}</span><span className="text-xs text-muted-foreground">{host.error || String(host.candidates.length) + " candidato(s)"}</span></div>)}</div></details> : null}
        <div className="flex flex-wrap gap-2">{selected.status === "running" && <Button variant="outline" size="sm" onClick={() => void stop()}><SquareIcon className="size-3" /> Interromper</Button>}<Button variant="outline" size="sm" asChild><Link href={"/function/tasks/detail?id=" + selected.campaign.task_id}>Abrir tarefa <ArrowRightIcon className="size-4" /></Link></Button></div>
      </CardContent></Card>}

      <Dialog open={plan !== null} onOpenChange={(open) => { if (!open) { setPlan(null); setScopeConfirmed(false); } }}>
        <DialogContent className="sm:max-w-xl">
          <DialogHeader><DialogTitle>Revisar e iniciar</DialogTitle><DialogDescription>Confira o alcance exato antes de gerar tráfego.</DialogDescription></DialogHeader>
          {plan && <div className="space-y-4 text-sm">
            <div className="flex flex-wrap gap-2"><Badge variant="outline">{plan.targets.length} IPs</Badge><Badge variant="outline">{plan.port_count.toLocaleString("pt-BR")} portas TCP</Badge><Badge variant="outline">Até {new Date(plan.expires_at).toLocaleString("pt-BR")}</Badge></div>
            <details className="rounded-lg border border-border p-3" open><summary className="cursor-pointer font-medium">IPs incluídos</summary><div className="mt-3 max-h-48 overflow-auto font-mono text-xs text-muted-foreground">{plan.targets.map((target) => <div key={target}>{target}</div>)}</div></details>
            <label className="flex cursor-pointer items-start gap-3 rounded-lg border border-border p-3"><input type="checkbox" className="mt-1 accent-primary" checked={scopeConfirmed} onChange={(event) => setScopeConfirmed(event.target.checked)} /><span>Confirmei autorização, janela e origem de rede para todos esses IPs.</span></label>
          </div>}
          <DialogFooter><Button variant="outline" onClick={() => setPlan(null)}>Voltar</Button><Button disabled={!scopeConfirmed || busy || !capabilities?.scanner_available} onClick={() => void start()}>{busy && <Loader2Icon className="size-4 animate-spin" />} Iniciar discovery</Button></DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
