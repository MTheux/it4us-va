"use client";

import * as React from "react";
import { DownloadIcon, FileCode2Icon, FileJson2Icon, FilesIcon, FolderIcon, SearchIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { api } from "@/lib/api";
import type { VAFile } from "@/lib/types";
import { cn } from "@/lib/utils";

const groups: Record<string, string> = {
  root: "Execução",
  hosts: "Hosts processados",
  raw: "Saída do scanner",
  deep: "VA aprofundado",
};

export function VAFiles({ runID }: { runID?: string }) {
  const [files, setFiles] = React.useState<VAFile[]>([]);
  const [selected, setSelected] = React.useState("");
  const [preview, setPreview] = React.useState("");
  const [search, setSearch] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState("");

  React.useEffect(() => {
    setFiles([]);
    setSelected("");
    setPreview("");
    setSearch("");
    if (!runID) return;
    let active = true;
    async function refresh() {
      try {
        const next = await api.vaFiles(runID!);
        if (active) setFiles(next);
      } catch {
        if (active) setError("Não foi possível carregar os arquivos da execução.");
      }
    }
    void refresh();
    const timer = window.setInterval(() => void refresh(), 3000);
    return () => { active = false; window.clearInterval(timer); };
  }, [runID]);

  React.useEffect(() => {
    if (!runID || !selected) return;
    let active = true;
    setLoading(true);
    setError("");
    api.vaFile(runID, selected).then(async (value) => {
      if (active) setPreview(typeof value === "string" ? value : await value.text());
    }).catch(() => {
      if (active) setError("Não foi possível abrir este arquivo.");
    }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [runID, selected]);

  async function download(file: VAFile) {
    if (!runID) return;
    try {
      const value = await api.vaFile(runID, file.path, true);
      const blob = value instanceof Blob ? value : new Blob([value]);
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = file.path.split("/").pop() || "evidencia.txt";
      link.click();
      URL.revokeObjectURL(url);
    } catch {
      setError("Não foi possível baixar este arquivo.");
    }
  }

  const current = files.find((file) => file.path === selected);
  const filtered = files.filter((file) => `${file.name} ${file.path}`.toLocaleLowerCase("pt-BR").includes(search.toLocaleLowerCase("pt-BR")));
  const grouped = ["root", "hosts", "raw", "deep"].map((group) => ({
    group,
    files: filtered.filter((file) => (file.path.includes("/") ? file.path.split("/")[0] : "root") === group),
  })).filter((entry) => entry.files.length);

  return <div className="grid min-h-0 flex-1 grid-cols-1 overflow-hidden lg:grid-cols-[21rem_minmax(0,1fr)]" aria-label="Arquivos da execução">
    <div className="flex min-h-[260px] flex-col border-b bg-background/30 lg:min-h-0 lg:border-b-0 lg:border-r">
      <div className="border-b p-4">
        <div className="flex items-center gap-2"><FilesIcon className="size-4 text-primary" /><h3 className="text-sm font-semibold">Arquivos da tarefa</h3><span className="ml-auto font-mono text-xs text-muted-foreground">{files.length}</span></div>
        <p className="mt-1 text-xs text-muted-foreground">Plano, histórico, inventário e saídas preservadas.</p>
        <div className="relative mt-3"><SearchIcon className="absolute left-2.5 top-2.5 size-4 text-muted-foreground" /><Input aria-label="Buscar arquivos" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Buscar arquivos" className="pl-9" /></div>
      </div>
      <div className="min-h-0 flex-1 overflow-y-auto p-2">
        {!runID ? <p className="p-4 text-sm text-muted-foreground">Selecione uma execução para consultar os arquivos.</p> : grouped.length === 0 ? <p className="p-4 text-sm text-muted-foreground">{search ? "Nenhum arquivo encontrado." : "Os arquivos aparecem conforme a execução avança."}</p> : grouped.map(({ group, files: items }) => <div key={group} className="mb-3">
          <div className="flex items-center gap-2 px-3 py-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground"><FolderIcon className="size-3.5" />{groups[group]}</div>
          {items.map((file) => <button key={file.path} type="button" onClick={() => setSelected(file.path)} className={cn("flex w-full items-center gap-2 rounded-md px-3 py-2 text-left text-sm hover:bg-accent", selected === file.path && "bg-primary/10 text-primary")}>
            {file.path.endsWith(".xml") ? <FileCode2Icon className="size-4 shrink-0" /> : <FileJson2Icon className="size-4 shrink-0" />}
            <span className="min-w-0 flex-1 truncate">{file.name}</span><span className="text-[10px] tabular-nums text-muted-foreground">{Math.max(1, Math.ceil(file.size / 1024))} KB</span>
          </button>)}
        </div>)}
      </div>
    </div>
    <div className="flex min-h-[360px] min-w-0 flex-col lg:min-h-0">
      {current ? <><div className="flex shrink-0 flex-wrap items-center gap-2 border-b px-4 py-3"><FileCode2Icon className="size-4 text-primary" /><div className="min-w-0 flex-1"><p className="truncate text-sm font-semibold">{current.name}</p><p className="truncate font-mono text-[10px] text-muted-foreground">{current.path} · SHA-256 {current.sha256.slice(0, 16)}…</p></div><Button size="sm" variant="outline" onClick={() => void download(current)}><DownloadIcon /> Baixar</Button></div><pre className="min-h-0 flex-1 overflow-auto whitespace-pre-wrap break-all p-5 font-mono text-xs leading-5 text-foreground/80">{loading ? "Carregando…" : preview}</pre></> : <div className="flex min-h-0 flex-1 flex-col items-center justify-center gap-3 px-8 text-center"><FilesIcon className="size-9 text-primary/50" /><p className="text-sm font-semibold">Selecione um arquivo</p><p className="max-w-sm text-xs leading-5 text-muted-foreground">Cada etapa registra evidências e recibos nesta execução. A prévia preserva o conteúdo original como texto.</p></div>}
      {error && <p role="alert" className="border-t p-3 text-xs text-destructive">{error}</p>}
    </div>
  </div>;
}
