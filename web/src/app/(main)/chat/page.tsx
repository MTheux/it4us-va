"use client";

import * as React from "react";
import Link from "next/link";
import { ArrowRightIcon, ArrowUpIcon, BotIcon, CheckCircle2Icon, Clock3Icon, Loader2Icon, NetworkIcon, RadarIcon, ShieldCheckIcon } from "lucide-react";
import { toast } from "sonner";

import { Transcript } from "@/components/transcript";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { Activity, Task, VARun } from "@/lib/types";
import { cn } from "@/lib/utils";

import LegacyChatPage from "./legacy-chat";

const runLabels: Record<VARun["status"], string> = {
  running: "Em execução", completed: "Concluída", partial: "Parcial",
  failed: "Falhou", canceled: "Cancelada", interrupted: "Interrompida",
};

function taskTitle(task: Task) {
  return task.name || `Tarefa #${task.id}`;
}

function TaskVAChat() {
  const [tasks, setTasks] = React.useState<Task[]>([]);
  const [runs, setRuns] = React.useState<VARun[]>([]);
  const [selectedTaskID, setSelectedTaskID] = React.useState("");
  const [requestedRunID, setRequestedRunID] = React.useState("");
  const [runDetail, setRunDetail] = React.useState<VARun | null>(null);
  const [activity, setActivity] = React.useState<Activity[]>([]);
  const [segment, setSegment] = React.useState(0);
  const [chatBusy, setChatBusy] = React.useState(false);
  const [input, setInput] = React.useState("");
  const [sending, setSending] = React.useState(false);
  const [loaded, setLoaded] = React.useState(false);
  const [error, setError] = React.useState("");
  const transcriptRef = React.useRef<HTMLDivElement>(null);

  React.useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    setSelectedTaskID(params.get("task") || "");
    setRequestedRunID(params.get("run") || "");
  }, []);

  React.useEffect(() => {
    let alive = true;
    async function refresh() {
      const [taskResult, runResult] = await Promise.allSettled([api.tasks(), api.vaRuns()]);
      if (!alive) return;
      if (taskResult.status === "fulfilled") {
        const next = taskResult.value.tasks.filter((task) => task.va_only);
        setTasks(next);
        setSelectedTaskID((current) => current || next[0]?.id || "");
        setLoaded(true);
      } else {
        setError("Não foi possível carregar as tarefas VA.");
        setLoaded(true);
      }
      if (runResult.status === "fulfilled") setRuns(runResult.value);
    }
    void refresh();
    const timer = window.setInterval(() => void refresh(), 3000);
    return () => { alive = false; window.clearInterval(timer); };
  }, []);

  const selectedTask = tasks.find((task) => task.id === selectedTaskID);
  const taskRuns = runs.filter((run) => String(run.campaign.task_id) === selectedTaskID);
  const chosenRun = taskRuns.find((run) => run.id === requestedRunID) || taskRuns[0];

  React.useEffect(() => {
    if (!selectedTaskID) return;
    const url = new URL(window.location.href);
    url.searchParams.set("task", selectedTaskID);
    if (requestedRunID) url.searchParams.set("run", requestedRunID);
    else url.searchParams.delete("run");
    window.history.replaceState(null, "", url);
  }, [selectedTaskID, requestedRunID]);

  React.useEffect(() => {
    setRunDetail(null);
    if (!chosenRun) return;
    let alive = true;
    async function refresh() {
      try {
        const detail = await api.vaRun(chosenRun!.id);
        if (alive) setRunDetail(detail);
      } catch {
        if (alive) setRunDetail(chosenRun!);
      }
    }
    void refresh();
    const timer = window.setInterval(() => void refresh(), 2000);
    return () => { alive = false; window.clearInterval(timer); };
  }, [chosenRun?.id]);

  React.useEffect(() => {
    setActivity([]);
    setChatBusy(false);
    if (!selectedTaskID) return;
    let alive = true;
    async function refresh() {
      const [sessionResult, busyResult] = await Promise.allSettled([api.mainSessions(selectedTaskID), api.chatStatus(selectedTaskID)]);
      if (!alive) return;
      const nextSegment = sessionResult.status === "fulfilled" ? sessionResult.value.current : 0;
      if (sessionResult.status === "fulfilled") setSegment(nextSegment);
      if (busyResult.status === "fulfilled") setChatBusy(busyResult.value.running);
      try {
        const history = await api.activityHistory(selectedTaskID, `main:${nextSegment}`, 0, 200);
        if (alive) setActivity(history.items);
      } catch {
        if (alive) setError("Não foi possível carregar a conversa desta tarefa.");
      }
    }
    void refresh();
    const timer = window.setInterval(() => void refresh(), 2000);
    return () => { alive = false; window.clearInterval(timer); };
  }, [selectedTaskID]);

  React.useEffect(() => {
    const viewport = transcriptRef.current;
    if (viewport) viewport.scrollTop = viewport.scrollHeight;
  }, [activity.length, selectedTaskID]);

  async function send() {
    const text = input.trim();
    if (!selectedTask || !text || sending || chatBusy) return;
    setSending(true);
    setError("");
    try {
      await api.chat(text, selectedTask.id, undefined, segment, chosenRun?.id);
      setInput("");
      setChatBusy(true);
    } catch (cause) {
      toast.error(cause instanceof Error ? cause.message : "Não foi possível enviar a mensagem.");
    } finally {
      setSending(false);
    }
  }

  const run = runDetail?.id === chosenRun?.id ? runDetail : chosenRun;
  const done = run && run.status !== "running";
  const progress = run?.total_hosts ? Math.min(100, Math.round(((run.completed_hosts + run.failed_hosts) / run.total_hosts) * 100)) : 0;
  const hosts = run?.result?.hosts ?? [];

  return (
    <div data-content-padding="false" className="mx-auto flex min-h-[calc(100svh-3rem)] w-full max-w-7xl flex-col gap-5 px-4 py-5 lg:h-[calc(100svh-4rem)] lg:min-h-0 lg:overflow-hidden lg:px-10">
      <header className="flex shrink-0 flex-wrap items-end justify-between gap-3 border-b pb-5">
        <div>
          <p className="font-mono text-[11px] font-medium uppercase tracking-[0.2em] text-primary">SOC / ACOMPANHAMENTO VA</p>
          <h1 className="mt-2 font-[family-name:var(--font-display)] text-3xl font-semibold tracking-tight sm:text-4xl">Chat da tarefa</h1>
          <p className="mt-2 text-sm text-muted-foreground">Uma conversa por tarefa para acompanhar a execução e analisar os resultados.</p>
        </div>
        <Button asChild size="sm" variant="outline"><Link href="/function/va-runs"><RadarIcon /> Nova execução</Link></Button>
      </header>

      <div className="flex min-h-0 flex-1 flex-col gap-3 lg:grid lg:grid-cols-[16rem_minmax(0,1fr)]">
        <aside className="hidden min-h-0 flex-col overflow-hidden rounded-xl border bg-card/50 lg:flex">
          <div className="border-b px-4 py-3"><p className="text-sm font-semibold">Tarefas VA</p><p className="text-xs text-muted-foreground">{tasks.length} cadastrada(s)</p></div>
          <div className="min-h-0 flex-1 overflow-y-auto p-2">
            {tasks.map((task) => {
              const activeRun = runs.find((item) => String(item.campaign.task_id) === task.id && item.status === "running");
              return <button type="button" key={task.id} onClick={() => { setSelectedTaskID(task.id); setRequestedRunID(""); }} className={cn("mb-1 flex w-full items-start gap-2 rounded-lg px-3 py-3 text-left hover:bg-accent/60", selectedTaskID === task.id && "bg-primary/10 text-primary")}>
                <NetworkIcon className="mt-0.5 size-4 shrink-0" />
                <span className="min-w-0 flex-1"><span className="block truncate text-sm font-medium">{taskTitle(task)}</span><span className="mt-1 block font-mono text-[11px] text-muted-foreground">#{task.id}{activeRun ? " · VA em execução" : ""}</span></span>
                {activeRun && <span className="mt-1 size-1.5 shrink-0 animate-pulse rounded-full bg-primary" />}
              </button>;
            })}
            {loaded && tasks.length === 0 && <p className="px-3 py-6 text-center text-xs text-muted-foreground">Nenhuma tarefa VA cadastrada.</p>}
          </div>
        </aside>

        <div className="flex min-h-0 min-w-0 flex-1 flex-col gap-3">
          <div className="lg:hidden"><Select value={selectedTaskID} onValueChange={(id) => { setSelectedTaskID(id); setRequestedRunID(""); }}><SelectTrigger className="w-full"><SelectValue placeholder="Selecionar tarefa VA" /></SelectTrigger><SelectContent>{tasks.map((task) => <SelectItem key={task.id} value={task.id}>{taskTitle(task)} · #{task.id}</SelectItem>)}</SelectContent></Select></div>
          {!selectedTask ? (
            <div className="flex min-h-0 flex-1 flex-col items-center justify-center gap-3 rounded-xl border bg-card/40 p-8 text-center"><BotIcon className="size-8 text-primary" /><h2 className="font-semibold">{loaded ? "Selecione ou crie uma tarefa VA" : "Carregando tarefas…"}</h2><p className="max-w-sm text-sm text-muted-foreground">{error || "O acompanhamento começa quando uma execução VA é iniciada para a tarefa."}</p><Button asChild size="sm"><Link href="/function/tasks">Ver tarefas <ArrowRightIcon /></Link></Button></div>
          ) : (
            <>
              <div className="shrink-0 rounded-xl border bg-card/50 p-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="min-w-0"><p className="font-mono text-[10px] uppercase tracking-widest text-primary">TAREFA #{selectedTask.id}</p><h2 className="mt-1 truncate text-lg font-semibold">{taskTitle(selectedTask)}</h2><p className="mt-1 text-xs text-muted-foreground">{taskRuns.length} execução(ões) VA vinculada(s)</p></div>
                  <Button asChild variant="ghost" size="sm"><Link href={`/function/tasks/detail?id=${selectedTask.id}`}>Ver tarefa <ArrowRightIcon /></Link></Button>
                </div>
                {taskRuns.length > 1 && <div className="mt-3 flex gap-2 overflow-x-auto pb-1">{taskRuns.map((item) => <button key={item.id} type="button" onClick={() => setRequestedRunID(item.id)} className={cn("shrink-0 rounded-md border px-2 py-1 font-mono text-[11px]", run?.id === item.id ? "border-primary text-primary" : "text-muted-foreground")}>{new Date(item.created_at).toLocaleString("pt-BR", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" })}</button>)}</div>}
                {run ? <div className="mt-4 space-y-3 border-t pt-3">
                  <div className="flex flex-wrap items-center gap-2 text-xs"><Badge variant={run.status === "running" ? "default" : "secondary"}>{runLabels[run.status]}</Badge><span className="text-muted-foreground">{run.phase === "cve_review" ? "Correlação de CVEs" : run.status === "running" ? "Discovery e checks de infraestrutura" : "Execução finalizada"}</span><span className="ml-auto font-mono tabular-nums">{run.completed_hosts + run.failed_hosts}/{run.total_hosts} hosts</span></div>
                  <div role="progressbar" aria-valuenow={progress} aria-valuemin={0} aria-valuemax={100} aria-label="Progresso da execução VA" className="h-1.5 overflow-hidden rounded-full bg-muted"><div className="h-full rounded-full bg-primary transition-[width]" style={{ width: `${progress}%` }} /></div>
                  <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground"><span>{run.candidate_count} candidato(s)</span><span>{run.failed_hosts} host(s) com falha</span><span>{run.campaign.depth === "deep" ? "Discovery + VA aprofundado" : "Discovery"}</span><span>{run.campaign.ports.length ? `${run.campaign.ports.length} portas` : "Todas as portas"}</span></div>
                  {run.error && <p className="text-xs text-destructive">{run.error}</p>}
                  {hosts.length > 0 && <details open={run.status === "running"} className="text-xs"><summary className="cursor-pointer font-medium text-foreground">Hosts processados ({hosts.length})</summary><div className="mt-2 max-h-36 space-y-1 overflow-y-auto">{hosts.map((host) => <div key={host.target} className="flex flex-wrap items-center gap-2 rounded border px-2 py-1"><code>{host.target}</code><span className="text-muted-foreground">{host.services?.length ?? 0} serviço(s) · {host.candidates?.length ?? 0} candidato(s)</span><span className="ml-auto">{host.status === "completed" ? "Concluído" : "Falhou"}</span></div>)}</div></details>}
                  {done && <Button asChild size="sm" variant="outline"><Link href={`/function/va-runs?task=${selectedTask.id}&depth=deep`}>Planejar aprofundamento <ArrowRightIcon /></Link></Button>}
                </div> : <div className="mt-4 flex items-center gap-2 border-t pt-3 text-xs text-muted-foreground"><Clock3Icon className="size-4" /> Nenhuma execução VA nesta tarefa. <Link href={`/function/va-runs?task=${selectedTask.id}`} className="text-primary hover:underline">Criar execução</Link></div>}
              </div>

              <section className="flex min-h-[360px] flex-1 flex-col overflow-hidden rounded-xl border bg-card/50 lg:min-h-0" aria-label="Conversa da tarefa">
                <div className="flex shrink-0 items-center justify-between gap-2 border-b px-4 py-3"><div className="flex items-center gap-2"><BotIcon className="size-4 text-primary" /><h3 className="text-sm font-semibold">Análise da tarefa</h3></div><span className="flex items-center gap-1 text-xs text-muted-foreground">{chatBusy ? <><Loader2Icon className="size-3.5 animate-spin" /> Analisando</> : <><ShieldCheckIcon className="size-3.5" /> Baseada no recibo VA</>}</span></div>
                <div ref={transcriptRef} className="min-h-0 flex-1 overflow-y-auto px-4 py-4">
                  {run && <div className="mb-5 space-y-2 border-l border-primary/30 pl-4 text-xs">
                    <p className="font-semibold text-foreground">Scanner · {new Date(run.created_at).toLocaleString("pt-BR")}</p>
                    <p className="text-muted-foreground">Execução iniciada com {run.total_hosts} host(s) e {run.campaign.ports.length ? `${run.campaign.ports.length} portas TCP` : "todas as portas TCP"}. Escopo revisado antes da partida.</p>
                    {hosts.map((host) => <p key={host.target} className="text-muted-foreground"><code className="text-foreground">{host.target}</code> · {host.status === "completed" ? `${host.services?.length ?? 0} serviço(s) observado(s), ${host.candidates?.length ?? 0} candidato(s)` : `falha: ${host.error || "consulte o recibo"}`}</p>)}
                    {run.phase === "cve_review" && <p className="text-primary">Correlacionando versões observadas com CVEs…</p>}
                    {done && <p className="font-medium text-foreground">Execução {runLabels[run.status].toLowerCase()}. {run.candidate_count} candidato(s) para triagem.</p>}
                    {run.status === "running" && run.phase !== "cve_review" && <p className="flex items-center gap-1 text-primary"><Loader2Icon className="size-3 animate-spin" /> Scanner em execução. Novos hosts aparecem aqui automaticamente.</p>}
                  </div>}
                  {activity.length ? <Transcript activity={activity} live={chatBusy} chat taskId={selectedTask.id} /> : <div className="flex min-h-32 flex-col items-center justify-center gap-2 text-center"><CheckCircle2Icon className="size-6 text-primary" /><p className="text-sm font-medium">Conversa pronta para esta tarefa</p><p className="max-w-md text-xs leading-5 text-muted-foreground">Pergunte sobre a execução ou peça um plano de aprofundamento com base no recibo VA.</p></div>}
                </div>
                {done && <div className="flex shrink-0 flex-wrap gap-2 border-t px-4 py-2"><button type="button" onClick={() => setInput("Resuma os serviços e candidatos observados nesta execução.")} className="rounded-full border px-3 py-1 text-xs text-muted-foreground hover:border-primary hover:text-primary">Resumir resultados</button><button type="button" onClick={() => setInput("Quais evidências faltam e qual aprofundamento de infraestrutura você recomenda dentro do escopo?")} className="rounded-full border px-3 py-1 text-xs text-muted-foreground hover:border-primary hover:text-primary">Planejar aprofundamento</button></div>}
                <div className="shrink-0 border-t p-3"><div className="flex items-end gap-2 rounded-lg border bg-background px-3 py-2 focus-within:border-primary"><label htmlFor="task-va-chat-input" className="sr-only">Mensagem para análise VA</label><Textarea id="task-va-chat-input" value={input} onChange={(event) => setInput(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter" && !event.shiftKey) { event.preventDefault(); void send(); } }} disabled={chatBusy || sending} rows={1} placeholder={chatBusy ? "Aguarde a análise terminar…" : "Pergunte sobre os resultados desta tarefa…"} className="max-h-28 min-h-9 flex-1 resize-none border-0 bg-transparent p-0 text-sm shadow-none focus-visible:ring-0" /><Button size="icon-sm" onClick={() => void send()} disabled={!input.trim() || chatBusy || sending} aria-label="Enviar mensagem"><ArrowUpIcon /></Button></div><p className="mt-2 text-[11px] text-muted-foreground">O chat analisa recibos existentes. Novos checks exigem revisão em Execuções VA.</p>{error && <p role="alert" className="mt-1 text-xs text-destructive">{error}</p>}</div>
              </section>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

export default function ChatPage() {
  const [legacy, setLegacy] = React.useState<boolean | null>(null);
  React.useEffect(() => setLegacy(new URLSearchParams(window.location.search).has("c")), []);
  if (legacy === null) return null;
  return legacy ? <LegacyChatPage /> : <TaskVAChat />;
}
