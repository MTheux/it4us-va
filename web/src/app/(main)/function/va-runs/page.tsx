"use client";

import * as React from "react";
import Link from "next/link";
import { ArrowRightIcon, CheckCircle2Icon, CircleDashedIcon, Loader2Icon, ScanSearchIcon, SquareIcon } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { Task, VACampaign, VAPlan, VARun } from "@/lib/types";

const commonPorts = "21,22,25,53,80,110,135,139,143,443,445,587,993,995,1433,1521,3306,3389,5432,5900,8080,8443";

function parsePorts(raw: string): number[] {
  const ports = new Set<number>();
  for (const piece of raw.split(/[\s,;]+/).filter(Boolean)) {
    const match = /^(\d{1,5})(?:-(\d{1,5}))?$/.exec(piece);
    if (!match) throw new Error(`Porta ou intervalo inválido: ${piece}`);
    const start = Number(match[1]);
    const end = Number(match[2] ?? match[1]);
    if (start < 1 || end > 65535 || end < start || end - start > 999) throw new Error(`Intervalo inválido: ${piece}`);
    for (let port = start; port <= end; port++) ports.add(port);
    if (ports.size > 1000) throw new Error("Esta versão aceita até 1.000 portas TCP por campanha.");
  }
  if (!ports.size) throw new Error("Informe ao menos uma porta TCP.");
  return [...ports].sort((a, b) => a - b);
}

function initialExpiry() {
  const date = new Date(Date.now() + 2 * 60 * 60 * 1000);
  const local = new Date(date.getTime() - date.getTimezoneOffset() * 60000);
  return local.toISOString().slice(0, 16);
}

const statusLabels: Record<VARun["status"], string> = {
  running: "Em execução",
  completed: "Concluída",
  partial: "Parcial",
  failed: "Falhou",
  canceled: "Cancelada",
  interrupted: "Interrompida",
};

export default function VARunsPage() {
  const [tasks, setTasks] = React.useState<Task[]>([]);
  const [runs, setRuns] = React.useState<VARun[]>([]);
  const [selected, setSelected] = React.useState<VARun | null>(null);
  const [taskID, setTaskID] = React.useState("");
  const [name, setName] = React.useState("");
  const [approvedBy, setApprovedBy] = React.useState("");
  const [expires, setExpires] = React.useState("");
  const [targets, setTargets] = React.useState("");
  const [ports, setPorts] = React.useState(commonPorts);
  const [plan, setPlan] = React.useState<VAPlan | null>(null);
  const [planSignature, setPlanSignature] = React.useState("");
  const [scopeConfirmed, setScopeConfirmed] = React.useState(false);
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState("");

  React.useEffect(() => { setExpires(initialExpiry()); }, []);
  const refresh = React.useCallback(async () => {
    const [taskResult, runResult] = await Promise.allSettled([api.tasks(), api.vaRuns()]);
    if (taskResult.status === "fulfilled") setTasks(taskResult.value.tasks);
    if (runResult.status === "fulfilled") setRuns(runResult.value);
    if (runResult.status === "rejected") setError(runResult.reason instanceof Error ? runResult.reason.message : "Falha ao carregar execuções");
  }, []);
  React.useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => void refresh(), 5000);
    return () => window.clearInterval(timer);
  }, [refresh]);
  React.useEffect(() => {
    if (!selected || selected.status !== "running") return;
    const current = runs.find((run) => run.id === selected.id);
    if (!current) return;
    if (current.status === "running" && current.completed_hosts === selected.completed_hosts && current.failed_hosts === selected.failed_hosts) return;
    void api.vaRun(selected.id).then(setSelected).catch(() => undefined);
  }, [runs, selected]);

  function campaign(): VACampaign {
    if (!taskID || !Number.isInteger(Number(taskID)) || Number(taskID) <= 0) throw new Error("Selecione uma tarefa do SOC.");
    if (!name.trim() || !approvedBy.trim()) throw new Error("Informe o nome da campanha e o responsável pela autorização.");
    const expiry = new Date(expires);
    if (!Number.isFinite(expiry.getTime()) || expiry.getTime() <= Date.now()) throw new Error("Escolha uma janela futura para a campanha.");
    const targetList = targets.split(/[\s,;]+/).filter(Boolean);
    if (!targetList.length) throw new Error("Informe os IPs ou ranges CIDR autorizados.");
    return {
      name: name.trim(), task_id: Number(taskID), approved_by: approvedBy.trim(),
      expires_at: expiry.toISOString(), targets: targetList, ports: parsePorts(ports),
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
      setError(cause instanceof Error ? cause.message : "Não foi possível validar a campanha.");
    } finally { setBusy(false); }
  }

  async function start() {
    if (!plan || signature() !== planSignature || !scopeConfirmed) return;
    setBusy(true);
    setError("");
    try {
      const run = await api.vaStart(campaign());
      setSelected(run);
      setPlan(null);
      setPlanSignature("");
      setScopeConfirmed(false);
      await refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Não foi possível iniciar a campanha.");
    } finally { setBusy(false); }
  }

  async function viewRun(id: string) {
    try { setSelected(await api.vaRun(id)); } catch (cause) { setError(cause instanceof Error ? cause.message : "Não foi possível carregar o recibo."); }
  }

  async function stop() {
    if (!selected || selected.status !== "running") return;
    try { await api.vaCancel(selected.id); await viewRun(selected.id); } catch (cause) { setError(cause instanceof Error ? cause.message : "Não foi possível interromper."); }
  }

  const planCurrent = !!plan && signature() === planSignature;

  return (
    <div className="mx-auto flex max-w-7xl flex-col gap-8 p-6 pb-16 md:p-10">
      <header className="space-y-3 border-b border-border pb-7">
        <p className="font-mono text-xs font-semibold uppercase tracking-[0.2em] text-primary">IT4US VA / Operação</p>
        <h1 className="flex items-center gap-3 text-3xl font-semibold tracking-tight md:text-4xl"><ScanSearchIcon className="size-8 text-primary" /> Execuções VA</h1>
        <p className="max-w-3xl text-sm leading-6 text-muted-foreground">
          Planeje um escopo, veja os IPs exatos e execute discovery TCP/serviços no worker instalado na rede do cliente. Os resultados entram como candidatos pendentes na tarefa.
        </p>
      </header>

      <div className="grid gap-4 md:grid-cols-4">
        {[
          ["01", "Escopo", "IPs, ranges e janela"], ["02", "Discovery", "Portas e serviços"],
          ["03", "Candidatos", "Evidências na tarefa"], ["04", "Revisão", "SOC e agente"],
        ].map(([number, title, description]) => (
          <Card key={number} className="bg-card/75"><CardContent className="pt-5"><span className="font-mono text-xs text-primary">{number}</span><h2 className="mt-2 font-semibold">{title}</h2><p className="mt-1 text-xs text-muted-foreground">{description}</p></CardContent></Card>
        ))}
      </div>

      <div className="grid items-start gap-6 xl:grid-cols-[minmax(0,1.2fr)_minmax(340px,0.8fr)]">
        <Card>
          <CardHeader><CardTitle>Nova campanha</CardTitle><p className="text-sm text-muted-foreground">Uma autorização cobre todos os alvos desta campanha. O plano mostra a expansão antes da execução.</p></CardHeader>
          <CardContent>
            <form className="space-y-5" onSubmit={preview}>
              <div className="grid gap-4 sm:grid-cols-2">
                <div className="space-y-2"><Label htmlFor="va-name">Nome da campanha</Label><Input id="va-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Ex.: VA interno novembro" /></div>
                <div className="space-y-2"><Label htmlFor="va-task">Tarefa associada</Label><select id="va-task" className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm focus-visible:outline-2 focus-visible:outline-primary" value={taskID} onChange={(e) => setTaskID(e.target.value)}><option value="">Selecione a tarefa</option>{tasks.map((task) => <option key={task.id} value={task.id}>{task.name || task.description || `Tarefa #${task.id}`} (#{task.id})</option>)}</select><Link href="/function/tasks" className="inline-flex items-center gap-1 text-xs text-primary hover:underline">Criar ou localizar tarefa <ArrowRightIcon className="size-3" /></Link></div>
                <div className="space-y-2"><Label htmlFor="va-approver">Responsável pela autorização</Label><Input id="va-approver" value={approvedBy} onChange={(e) => setApprovedBy(e.target.value)} placeholder="Nome ou equipe do SOC" /></div>
                <div className="space-y-2"><Label htmlFor="va-expiry">Fim da janela</Label><Input id="va-expiry" type="datetime-local" value={expires} onChange={(e) => setExpires(e.target.value)} /></div>
              </div>
              <div className="space-y-2"><Label htmlFor="va-targets">IPs e ranges CIDR autorizados</Label><Textarea id="va-targets" value={targets} onChange={(e) => setTargets(e.target.value)} rows={5} className="font-mono" placeholder={"192.0.2.10\n198.51.100.0/28"} /><p className="text-xs text-muted-foreground">Um IP ou CIDR por linha; também aceita vírgulas. Até 4.096 IPs expandidos nesta versão. Hostnames não são resolvidos.</p></div>
              <div className="space-y-2"><Label htmlFor="va-ports">Portas TCP</Label><Input id="va-ports" value={ports} onChange={(e) => setPorts(e.target.value)} className="font-mono" placeholder="22,80,443 ou 1-1000" /><p className="text-xs text-muted-foreground">Aceita listas e intervalos; até 1.000 portas por campanha.</p></div>
              <div className="flex flex-wrap gap-2"><Button type="button" variant="outline" size="sm" onClick={() => setPorts(commonPorts)}>Portas comuns</Button><Button type="button" variant="outline" size="sm" onClick={() => setPorts("1-1000")}>TCP 1–1000</Button></div>
              <Button type="submit" disabled={busy}>{busy && <Loader2Icon className="size-4 animate-spin" />} Validar plano</Button>
              {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
            </form>
          </CardContent>
        </Card>

        <div className="space-y-6">
          <Card className={planCurrent ? "border-primary/40" : ""}>
            <CardHeader><CardTitle>Plano de execução</CardTitle></CardHeader>
            <CardContent className="space-y-4">
              {planCurrent && plan ? (
                <>
                  <div className="flex flex-wrap gap-2"><Badge variant="outline">{plan.targets.length} IPs</Badge><Badge variant="outline">{plan.ports.length} portas TCP</Badge><Badge variant="outline">Tarefa #{plan.task_id}</Badge></div>
                  <p className="text-xs text-muted-foreground">Janela até {new Date(plan.expires_at).toLocaleString("pt-BR")}. A execução usará Nmap TCP connect e detecção de serviços, sem scripts NSE ou exploração automática.</p>
                  <details className="rounded-lg border border-border p-3 text-sm"><summary className="cursor-pointer font-medium">Ver todos os IPs expandidos</summary><div className="mt-3 max-h-44 overflow-auto font-mono text-xs text-muted-foreground">{plan.targets.map((target) => <div key={target}>{target}</div>)}</div></details>
                  <label className="flex items-start gap-2 text-sm"><input type="checkbox" className="mt-1 accent-primary" checked={scopeConfirmed} onChange={(e) => setScopeConfirmed(e.target.checked)} /><span>Confirmei escopo, janela e origem de rede para esta campanha.</span></label>
                  <Button className="w-full" disabled={!scopeConfirmed || busy} onClick={() => void start()}>Iniciar discovery</Button>
                </>
              ) : <p className="text-sm text-muted-foreground">Preencha a campanha e valide o plano para ver a lista exata de alvos antes de iniciar.</p>}
            </CardContent>
          </Card>
          <Card>
            <CardHeader><CardTitle>O que acontece depois</CardTitle></CardHeader>
            <CardContent className="space-y-3 text-sm text-muted-foreground">
              <p>Serviços encontrados viram candidatos pendentes na tarefa. O agente pode investigar esses candidatos no contexto da tarefa; esta versão ainda não inicia validações adicionais automaticamente.</p>
              <p>O SOC revisa cada candidato em <Link href="/function/findings" className="text-primary hover:underline">Achados</Link>. Porta aberta ou banner sozinho não confirma vulnerabilidade.</p>
            </CardContent>
          </Card>
        </div>
      </div>

      <section className="space-y-4">
        <div><p className="font-mono text-xs uppercase tracking-[0.2em] text-primary">Histórico</p><h2 className="mt-2 text-2xl font-semibold">Campanhas recentes</h2></div>
        {runs.length === 0 ? <Card><CardContent className="py-8 text-sm text-muted-foreground">Nenhuma campanha executada nesta instalação.</CardContent></Card> : (
          <div className="grid gap-3">{runs.map((run) => <button key={run.id} type="button" onClick={() => void viewRun(run.id)} className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-border bg-card p-4 text-left hover:border-primary/50"><div><p className="font-semibold">{run.campaign.name}</p><p className="mt-1 text-xs text-muted-foreground">{new Date(run.created_at).toLocaleString("pt-BR")} · Tarefa #{run.campaign.task_id}</p></div><div className="flex items-center gap-3 text-xs"><span>{run.completed_hosts + run.failed_hosts}/{run.total_hosts} hosts</span><span>{run.candidate_count} candidatos</span><Badge variant="outline" className={run.status === "completed" ? "border-primary/40 text-primary" : ""}>{statusLabels[run.status]}</Badge></div></button>)}</div>
        )}
      </section>

      {selected && <Card className="border-primary/25"><CardHeader><CardTitle className="flex flex-wrap items-center justify-between gap-3">Recibo · {selected.campaign.name}<Badge variant="outline">{statusLabels[selected.status]}</Badge></CardTitle></CardHeader><CardContent className="space-y-4"><div className="flex flex-wrap items-center gap-4 text-sm text-muted-foreground"><span>{selected.completed_hosts + selected.failed_hosts}/{selected.total_hosts} hosts verificados</span><span>{selected.candidate_count} candidatos</span>{selected.status === "running" && <Button variant="outline" size="sm" onClick={() => void stop()}><SquareIcon className="size-3" /> Interromper</Button>}</div>{selected.error && <p role="alert" className="text-sm text-destructive">{selected.error}</p>}{selected.result?.hosts?.length ? <div className="max-h-72 overflow-auto rounded-lg border border-border">{selected.result.hosts.map((host) => <div key={host.target} className="flex items-start justify-between gap-4 border-b border-border px-4 py-3 text-sm last:border-0"><div><p className="font-mono">{host.target}</p><p className="mt-1 text-xs text-muted-foreground">{host.error || `${host.candidates.length} candidato(s)`}</p></div>{host.status === "completed" ? <CheckCircle2Icon className="size-4 text-primary" /> : <CircleDashedIcon className="size-4 text-destructive" />}</div>)}</div> : <p className="text-sm text-muted-foreground">{selected.status === "running" ? "Discovery em andamento. O recibo por host aparece ao final; o progresso é atualizado automaticamente." : "Nenhum host verificado."}</p>}<Button variant="outline" asChild><Link href={`/function/tasks/detail?id=${selected.campaign.task_id}`}>Abrir tarefa e candidatos <ArrowRightIcon className="size-4" /></Link></Button></CardContent></Card>}
    </div>
  );
}
