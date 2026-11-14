"use client";

import * as React from "react";
import Link from "next/link";
import { ArrowRightIcon, ArrowUpIcon, BotIcon, Loader2Icon, NetworkIcon, ShieldCheckIcon } from "lucide-react";
import { toast } from "sonner";

import { Transcript } from "@/components/transcript";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { Activity, Task, VAEvent, VARun } from "@/lib/types";
import { cn } from "@/lib/utils";

import LegacyChatPage from "./legacy-chat";
import { VAFiles } from "./va-files";

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
  const [events, setEvents] = React.useState<VAEvent[]>([]);
  const [olderCursor, setOlderCursor] = React.useState(0);
  const [hasOlder, setHasOlder] = React.useState(false);
  const loadedOlderRef = React.useRef(false);
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
    setEvents([]);
    if (!chosenRun) return;
    let alive = true;
    async function refresh() {
      try {
        const [detail, history] = await Promise.all([api.vaRun(chosenRun!.id), api.vaEvents(chosenRun!.id)]);
        if (alive) { setRunDetail(detail); setEvents(history); }
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
    loadedOlderRef.current = false;
    setOlderCursor(0);
    setHasOlder(false);
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
        if (alive) {
          setActivity((current) => {
            const merged = new Map<number, Activity>();
            for (const item of [...current, ...history.items]) merged.set(item.seq, item);
            return [...merged.values()].sort((a, b) => a.seq - b.seq);
          });
          if (!loadedOlderRef.current) { setOlderCursor(history.earliestCursor); setHasOlder(history.hasMore); }
        }
      } catch {
        if (alive) setError("Não foi possível carregar a conversa desta tarefa.");
      }
    }
    void refresh();
    const timer = window.setInterval(() => void refresh(), 2000);
    return () => { alive = false; window.clearInterval(timer); };
  }, [selectedTaskID]);

  async function loadOlder() {
    if (!selectedTaskID || !hasOlder || !olderCursor) return;
    try {
      const history = await api.activityHistory(selectedTaskID, `main:${segment}`, olderCursor, 200);
      loadedOlderRef.current = true;
      setActivity((current) => [...history.items, ...current.filter((item) => !history.items.some((older) => older.seq === item.seq))]);
      setOlderCursor(history.earliestCursor);
      setHasOlder(history.hasMore);
    } catch {
      setError("Não foi possível carregar mensagens anteriores.");
    }
  }

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
    <div data-content-padding="false" className="mx-auto flex min-h-[calc(100svh-3rem)] w-full max-w-[1680px] flex-col gap-4 px-4 py-5 lg:h-[calc(100svh-4rem)] lg:min-h-0 lg:overflow-hidden lg:px-8">
      <header className="flex shrink-0 items-center justify-between gap-4 pb-1">
        <div>
          <p className="font-mono text-[10px] font-medium uppercase tracking-[0.2em] text-primary">GUARD4US / OPERAÇÃO VA</p>
          <h1 className="mt-1 font-[family-name:var(--font-display)] text-2xl font-semibold tracking-tight sm:text-3xl">Chat da tarefa</h1>
          <p className="mt-1 text-xs text-muted-foreground">Converse sobre a execução enquanto acompanha a trilha e as evidências.</p>
        </div>
        {selectedTask && <Button asChild size="sm" variant="ghost" className="hidden sm:inline-flex"><Link href={`/function/tasks/detail?id=${selectedTask.id}`}>Ver tarefa <ArrowRightIcon /></Link></Button>}
      </header>

      <div className="grid min-h-0 flex-1 gap-3 lg:grid-cols-[13.5rem_minmax(0,1fr)_21rem]">
        <aside className="hidden min-h-0 flex-col overflow-hidden rounded-2xl border border-border/70 bg-card/40 lg:flex" aria-label="Tarefas VA">
          <div className="border-b border-border/70 px-4 py-4"><p className="text-sm font-semibold">Tarefas VA</p><p className="mt-0.5 text-xs text-muted-foreground">{tasks.length} cadastrada(s)</p></div>
          <div className="min-h-0 flex-1 space-y-1 overflow-y-auto p-2">
            {tasks.map((task) => {
              const activeRun = runs.find((item) => String(item.campaign.task_id) === task.id && item.status === "running");
              return <button type="button" key={task.id} onClick={() => { setSelectedTaskID(task.id); setRequestedRunID(""); }} className={cn("flex w-full items-start gap-2 rounded-xl px-3 py-3 text-left transition-colors hover:bg-accent/60", selectedTaskID === task.id && "border border-primary/25 bg-primary/10 text-primary")}>
                <NetworkIcon className="mt-0.5 size-4 shrink-0" />
                <span className="min-w-0 flex-1"><span className="block truncate text-sm font-medium">{taskTitle(task)}</span><span className="mt-1 block font-mono text-[10px] text-muted-foreground">Tarefa #{task.id}</span></span>
                {activeRun && <span className="mt-1 size-1.5 shrink-0 animate-pulse rounded-full bg-primary" />}
              </button>;
            })}
            {loaded && tasks.length === 0 && <p className="px-3 py-6 text-center text-xs text-muted-foreground">Nenhuma tarefa VA cadastrada.</p>}
          </div>
        </aside>

        <div className="min-w-0 lg:hidden"><Select value={selectedTaskID} onValueChange={(id) => { setSelectedTaskID(id); setRequestedRunID(""); }}><SelectTrigger className="w-full"><SelectValue placeholder="Selecionar tarefa VA" /></SelectTrigger><SelectContent>{tasks.map((task) => <SelectItem key={task.id} value={task.id}>{taskTitle(task)} · #{task.id}</SelectItem>)}</SelectContent></Select></div>

        {!selectedTask ? <div className="flex min-h-[28rem] flex-col items-center justify-center gap-3 rounded-2xl border bg-card/40 p-8 text-center lg:col-span-2"><BotIcon className="size-8 text-primary" /><h2 className="font-semibold">{loaded ? "Selecione uma tarefa VA" : "Carregando tarefas…"}</h2><p className="max-w-sm text-sm text-muted-foreground">{error || "A conversa começa quando uma tarefa VA é selecionada."}</p><Button asChild size="sm"><Link href="/function/tasks">Ver tarefas <ArrowRightIcon /></Link></Button></div> : <>
          <section className="flex min-h-[32rem] min-w-0 flex-col overflow-hidden rounded-2xl border border-border/70 bg-card/50 lg:min-h-0" aria-label="Conversa da tarefa">
            <div className="flex shrink-0 items-center justify-between gap-3 border-b border-border/70 px-5 py-4">
              <div className="min-w-0"><p className="font-mono text-[10px] uppercase tracking-[0.16em] text-primary">TAREFA #{selectedTask.id}</p><h2 className="mt-1 truncate text-base font-semibold">{taskTitle(selectedTask)}</h2></div>
              <span className={cn("flex shrink-0 items-center gap-1.5 rounded-full px-2.5 py-1 text-[11px]", chatBusy ? "bg-primary/10 text-primary" : "bg-muted text-muted-foreground")}>{chatBusy ? <Loader2Icon className="size-3.5 animate-spin" /> : <BotIcon className="size-3.5" />}{chatBusy ? "Analisando" : "Chat disponível"}</span>
            </div>
            <div ref={transcriptRef} className="min-h-0 flex-1 space-y-5 overflow-y-auto px-4 py-5 sm:px-6">
              {hasOlder && <button type="button" onClick={() => void loadOlder()} className="rounded-md border px-3 py-1.5 text-xs text-primary hover:bg-primary/10">Carregar mensagens anteriores</button>}
              {activity.length ? <Transcript activity={activity} live={chatBusy} chat taskId={selectedTask.id} /> : <div className="flex min-h-64 flex-col items-center justify-center gap-3 text-center"><div className="flex size-12 items-center justify-center rounded-2xl bg-primary/10"><BotIcon className="size-6 text-primary" /></div><p className="text-sm font-semibold">Conversa pronta para esta tarefa</p><p className="max-w-sm text-xs leading-5 text-muted-foreground">Peça um resumo, esclareça um candidato ou solicite um plano de aprofundamento com base nos recibos.</p></div>}
            </div>
            {done && <div className="flex shrink-0 flex-wrap gap-2 border-t border-border/70 px-4 py-3 sm:px-6"><button type="button" onClick={() => setInput("Resuma os serviços e candidatos observados nesta execução.")} className="rounded-full border px-3 py-1.5 text-xs text-muted-foreground hover:border-primary hover:text-primary">Resumir resultados</button><button type="button" onClick={() => setInput("Quais evidências faltam e qual aprofundamento de infraestrutura você recomenda dentro do escopo?")} className="rounded-full border px-3 py-1.5 text-xs text-muted-foreground hover:border-primary hover:text-primary">Próximas validações</button></div>}
            <div className="shrink-0 border-t border-border/70 bg-background/30 px-4 py-3 sm:px-6"><div className="flex items-end gap-2 rounded-xl border bg-background px-3 py-2 focus-within:border-primary"><label htmlFor="task-va-chat-input" className="sr-only">Mensagem para análise VA</label><Textarea id="task-va-chat-input" value={input} onChange={(event) => setInput(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter" && !event.shiftKey) { event.preventDefault(); void send(); } }} disabled={chatBusy || sending} rows={1} placeholder={chatBusy ? "Aguarde a análise terminar…" : "Pergunte sobre esta tarefa…"} className="max-h-28 min-h-9 flex-1 resize-none border-0 bg-transparent p-0 text-sm shadow-none focus-visible:ring-0" /><Button size="icon-sm" onClick={() => void send()} disabled={!input.trim() || chatBusy || sending} aria-label="Enviar mensagem"><ArrowUpIcon /></Button></div><p className="mt-2 text-[10px] text-muted-foreground">O chat analisa recibos existentes; novas ações passam pelos controles da execução VA.</p>{error && <p role="alert" className="mt-1 text-xs text-destructive">{error}</p>}</div>
          </section>

          <aside className="min-h-0 space-y-3 overflow-y-auto rounded-2xl border border-border/70 bg-card/40 p-3 lg:p-4" aria-label="Contexto e evidências da execução">
            <div className="rounded-xl border border-border/70 bg-background/40 p-3">
              <div className="flex items-center justify-between gap-2"><p className="text-sm font-semibold">Execuções</p><span className="font-mono text-[11px] text-muted-foreground">{taskRuns.length}</span></div>
              {taskRuns.length > 0 ? <div className="mt-3 flex gap-2 overflow-x-auto pb-1">{taskRuns.map((item) => <button key={item.id} type="button" onClick={() => setRequestedRunID(item.id)} className={cn("shrink-0 rounded-lg border px-2.5 py-1.5 font-mono text-[10px]", run?.id === item.id ? "border-primary/50 bg-primary/10 text-primary" : "text-muted-foreground hover:text-foreground")}>{new Date(item.created_at).toLocaleString("pt-BR", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" })}</button>)}</div> : <p className="mt-2 text-xs text-muted-foreground">Nenhuma execução vinculada.</p>}
            </div>
            {run && <div className="space-y-3 rounded-xl border border-border/70 bg-background/40 p-3">
              <div className="flex items-center justify-between gap-2"><Badge variant={run.status === "running" ? "default" : "secondary"}>{runLabels[run.status]}</Badge><span className="font-mono text-[11px] tabular-nums">{run.completed_hosts + run.failed_hosts}/{run.total_hosts} hosts</span></div>
              <div role="progressbar" aria-valuenow={progress} aria-valuemin={0} aria-valuemax={100} aria-label="Progresso da execução VA" className="h-1.5 overflow-hidden rounded-full bg-muted"><div className="h-full rounded-full bg-primary transition-[width]" style={{ width: `${progress}%` }} /></div>
              <div className="grid grid-cols-2 gap-2 text-center"><div className="rounded-lg bg-muted/50 p-2"><strong className="block text-lg">{run.candidate_count}</strong><span className="text-[10px] text-muted-foreground">candidatos</span></div><div className="rounded-lg bg-muted/50 p-2"><strong className="block text-lg">{run.failed_hosts}</strong><span className="text-[10px] text-muted-foreground">hosts com falha</span></div></div>
              <p className="text-[11px] text-muted-foreground">{run.campaign.depth === "deep" ? "Discovery + VA aprofundado" : "Discovery"} · {run.campaign.ports.length ? `${run.campaign.ports.length} portas` : "Todas as portas"}</p>
              {run.draxen && <p className="flex items-center gap-1.5 text-[11px] text-muted-foreground"><ShieldCheckIcon className="size-3.5 text-primary" />Revisão Draxen: {run.draxen.status === "completed" ? `concluída · ${run.draxen.proposals ?? 0} propostas` : run.draxen.status === "unavailable" ? "indisponível" : "falhou"}</p>}
              {run.error && <p className="text-xs text-destructive">{run.error}</p>}
              {hosts.length > 0 && <details className="text-xs"><summary className="cursor-pointer font-medium">Hosts processados ({hosts.length})</summary><div className="mt-2 space-y-1">{hosts.map((host) => <div key={host.target} className="rounded-md border px-2 py-1.5"><code>{host.target}</code><span className="block text-[10px] text-muted-foreground">{host.services?.length ?? 0} serviços · {host.candidates?.length ?? 0} candidatos</span></div>)}</div></details>}
            </div>}
            {run && <details className="rounded-xl border border-border/70 bg-background/40 p-3 text-xs"><summary className="cursor-pointer font-semibold">Trilha da execução <span className="ml-1 font-mono font-normal text-muted-foreground">{events.length}</span></summary><div className="mt-3 max-h-52 space-y-2 overflow-y-auto border-l border-primary/30 pl-3">{events.length ? events.map((event, index) => <div key={`${event.at}-${index}`}><time className="font-mono text-[10px] text-muted-foreground">{new Date(event.at).toLocaleTimeString("pt-BR")}</time><p className="text-[11px]"><span className={event.status === "failed" ? "text-destructive" : "font-medium"}>{event.stage}</span>{event.target && <code className="ml-1 text-primary">{event.target}</code>}<span className="block text-muted-foreground">{event.detail || event.status}</span></p></div>) : <p className="text-muted-foreground">Nenhum evento detalhado.</p>}</div></details>}
            <div className="rounded-xl border border-border/70 bg-background/40 p-3"><VAFiles runID={run?.id} compact /></div>
          </aside>
        </>}
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
