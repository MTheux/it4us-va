"use client";

import * as React from "react";
import Link from "next/link";
import { CheckCircle2, Download, FileText, KeyRound, Loader2, PlugZap, RefreshCw, ShieldCheck } from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api } from "@/lib/api";
import type { Agent, LLMProfile, MCPServer, MCPTool } from "@/lib/types";

type Provider = "claude" | "opencode";
type DemoReport = { id: string; title: string; format: string; demo: boolean };
const CLAUDE_MODEL = "claude-sonnet-5";
const OPENCODE_MODEL = "claude-opus-4-8";
const OPENCODE_URL = "http://127.0.0.1:4096/v1";
const ROVO_URL = "https://mcp.atlassian.com/v2/mcp";

export default function ConnectionsPage() {
  const [profiles, setProfiles] = React.useState<LLMProfile[]>([]);
  const [servers, setServers] = React.useState<MCPServer[]>([]);
  const [agents, setAgents] = React.useState<Agent[]>([]);
  const [visibility, setVisibility] = React.useState<Record<number, string[]>>({});
  const [provider, setProvider] = React.useState<Provider>("claude");
  const [key, setKey] = React.useState("");
  const [model, setModel] = React.useState(CLAUDE_MODEL);
  const [aiState, setAiState] = React.useState<"idle" | "testing" | "connected" | "error">("idle");
  const [aiMessage, setAiMessage] = React.useState("");
  const [connectorName, setConnectorName] = React.useState("atlassian_rovo");
  const [connectorUrl, setConnectorUrl] = React.useState(ROVO_URL);
  const [connectorToken, setConnectorToken] = React.useState("");
  const [mcpBusy, setMcpBusy] = React.useState(false);
  const [busyServer, setBusyServer] = React.useState<number | null>(null);
  const [tools, setTools] = React.useState<Record<number, MCPTool[]>>({});
  const [reports, setReports] = React.useState<DemoReport[]>([]);
  const [reportText, setReportText] = React.useState("");
  const [reportName, setReportName] = React.useState("");

  const load = React.useCallback(async () => {
    const [ps, ss, aa] = await Promise.all([api.llmProfiles(), api.mcpServers(), api.agents()]);
    setProfiles(ps);
    setServers(ss);
    setAgents(aa);
    const pairs = await Promise.all(ss.map(async (s) => [s.id, await api.resourceVisibility("mcp", s.id).catch(() => [])] as const));
    setVisibility(Object.fromEntries(pairs));
    const found = await Promise.all(ss.map(async (s) => [s.id, await api.mcpTools(s.id).catch(() => [])] as const));
    setTools(Object.fromEntries(found));
  }, []);
  React.useEffect(() => { void load().catch((e) => toast.error((e as Error).message)); }, [load]);

  const profileName = provider === "claude" ? "SOC Claude" : "SOC OpenCode local";
  const savedProfile = profiles.find((p) => p.name === profileName);
  const activeProfile = profiles.find((p) => p.is_default);
  const demo = servers.find((s) => s.name === "soc_demo_reports");

  function chooseProvider(next: Provider) {
    setProvider(next);
    setModel(next === "claude" ? CLAUDE_MODEL : OPENCODE_MODEL);
    setKey("");
    setAiState("idle");
    setAiMessage("");
  }

  async function connectAI() {
    if (provider === "claude" && !key.trim() && !savedProfile?.api_key_hint) {
      toast.error("Informe a API key do Claude.");
      return;
    }
    if (!model.trim()) { toast.error("Informe o modelo."); return; }
    setAiState("testing");
    setAiMessage("Testando uma resposta real do modelo…");
    try {
      const format = provider === "claude" ? "anthropic" : "opencode";
      const baseURL = provider === "claude" ? "" : OPENCODE_URL;
      const result = await api.testLLM(format, model.trim(), baseURL, key.trim(), "", "", "", savedProfile ? Number(savedProfile.id) : undefined);
      if (!result.ok || !result.reply?.trim()) throw new Error(result.error || "O modelo não respondeu ao teste.");
      const saved = await api.saveLLMProfile({
        ...(savedProfile ? { id: Number(savedProfile.id) } : {}),
        name: profileName,
        format: provider === "claude" ? "anthropic" : "openai",
        model: model.trim(),
        base_url: baseURL,
        ...(key.trim() ? { api_key: key.trim() } : provider === "opencode" && !savedProfile ? { api_key: "opencode" } : {}),
        streaming: true,
      });
      await api.activateLLMProfile(String(saved.id));
      setKey("");
      setAiState("connected");
      setAiMessage(`Conectado · ${result.latency_ms ?? 0} ms · ${result.model || model.trim()}`);
      await load();
      toast.success("IA conectada e ativada para o VA.");
    } catch (error) {
      setAiState("error");
      setAiMessage((error as Error).message);
    }
  }

  async function saveConnector() {
    if (!/^[A-Za-z0-9_-]{1,64}$/.test(connectorName.trim()) || !/^https:\/\//i.test(connectorUrl.trim())) {
      toast.error("Use um identificador sem espaços e uma URL HTTPS do servidor MCP.");
      return;
    }
    setMcpBusy(true);
    try {
      const current = servers.find((s) => s.name === connectorName.trim());
      await api.saveMcpServer({
        ...(current ? { id: current.id } : {}), name: connectorName.trim(), transport: "http",
        url: connectorUrl.trim(), args: [], enabled: true, insecure: false,
        ...(connectorToken.trim() ? { env: { Authorization: `Bearer ${connectorToken.trim()}` } } : {}),
      });
      setConnectorToken("");
      await load();
      toast.success("Conector salvo. Teste a conexão na lista abaixo.");
    } catch (error) { toast.error((error as Error).message); }
    finally { setMcpBusy(false); }
  }

  async function testConnector(server: MCPServer) {
    setBusyServer(server.id);
    try {
      const found = await api.refreshMcpServer(server.id);
      setTools((old) => ({ ...old, [server.id]: found }));
      await load();
      toast.success(`${server.name}: ${found.length} ferramentas disponíveis.`);
    } catch (error) { toast.error(`Falha em ${server.name}: ${(error as Error).message}`); }
    finally { setBusyServer(null); }
  }

  async function bindAgent(server: MCPServer, agent: Agent) {
    const visible = (visibility[server.id] ?? []).includes(agent.id);
    try {
      await api.toggleVisibility(agent.id, "mcp", server.id, !visible);
      setVisibility((old) => ({ ...old, [server.id]: visible ? (old[server.id] ?? []).filter((id) => id !== agent.id) : [...(old[server.id] ?? []), agent.id] }));
    } catch (error) { toast.error((error as Error).message); }
  }

  async function listReports() {
    if (!demo) return;
    setBusyServer(demo.id);
    try {
      const result = await api.previewMcpTool(demo.id, "list_reports", {});
      if (result.is_error) throw new Error(result.output);
      const parsed: unknown = JSON.parse(result.output);
      if (!Array.isArray(parsed)) throw new Error("Resposta do catálogo inválida.");
      setReports(parsed.filter((r): r is DemoReport => typeof r === "object" && r !== null && typeof r.id === "string" && typeof r.title === "string"));
    } catch (error) { toast.error((error as Error).message); }
    finally { setBusyServer(null); }
  }

  async function openReport(report: DemoReport) {
    if (!demo) return;
    setBusyServer(demo.id);
    try {
      const result = await api.previewMcpTool(demo.id, "get_report", { report_id: report.id });
      if (result.is_error) throw new Error(result.output);
      setReportText(result.output);
      setReportName(report.id);
    } catch (error) { toast.error((error as Error).message); }
    finally { setBusyServer(null); }
  }

  function downloadReport() {
    if (!reportText || !reportName) return;
    const href = URL.createObjectURL(new Blob([reportText], { type: "text/markdown;charset=utf-8" }));
    const link = document.createElement("a");
    link.href = href;
    link.download = `${reportName}.md`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(href), 1000);
  }

  return (
    <div className="mx-auto w-full max-w-5xl space-y-6 p-4 md:p-6">
      <header className="space-y-1">
        <div className="flex items-center gap-2 text-sm font-medium text-primary"><PlugZap className="size-4" /> CONEXÕES DO SOC</div>
        <h1 className="text-2xl font-semibold tracking-tight">Conectar IA e agentes</h1>
        <p className="text-sm text-muted-foreground">Configure a chave uma vez, teste a conexão e escolha quais agentes podem usar cada MCP.</p>
      </header>

      <Card className="overflow-hidden">
        <CardContent className="space-y-5 p-5 md:p-6">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div><h2 className="flex items-center gap-2 font-semibold"><KeyRound className="size-4" /> IA do VA</h2><p className="mt-1 text-sm text-muted-foreground">A chave é enviada ao servidor e não reaparece na tela.</p></div>
            {activeProfile && <Badge variant="outline">Em uso: {activeProfile.name}</Badge>}
          </div>
          <div className="grid gap-2 sm:grid-cols-2">
            {(["claude", "opencode"] as const).map((choice) => (
              <button key={choice} type="button" onClick={() => chooseProvider(choice)} className={`rounded-xl border p-4 text-left transition-colors ${provider === choice ? "border-primary bg-primary/5" : "hover:bg-muted/50"}`}>
                <span className="block font-medium">{choice === "claude" ? "Claude API" : "OpenCode local"}</span>
                <span className="mt-1 block text-xs text-muted-foreground">{choice === "claude" ? "Cole uma API key da Anthropic." : "Usa a conta já conectada no OpenCode deste Mac."}</span>
              </button>
            ))}
          </div>
          <div className="grid gap-4 sm:grid-cols-[1fr_1fr_auto] sm:items-end">
            {provider === "claude" && <div className="space-y-2"><Label htmlFor="ai-key">API key</Label><Input id="ai-key" type="password" autoComplete="off" placeholder={savedProfile?.api_key_hint ? "Chave salva · deixe vazio para retestar" : "Cole sua chave aqui"} value={key} onChange={(e) => { setKey(e.target.value); setAiState("idle"); }} /></div>}
            <div className="space-y-2"><Label htmlFor="ai-model">Modelo</Label><Input id="ai-model" value={model} onChange={(e) => setModel(e.target.value)} /></div>
            <Button onClick={() => void connectAI()} disabled={aiState === "testing"} className="min-w-40">{aiState === "testing" ? <Loader2 className="animate-spin" /> : <ShieldCheck />} Testar e conectar</Button>
          </div>
          {aiState !== "idle" && <div role="status" className={`flex items-center gap-3 rounded-lg border p-3 text-sm ${aiState === "connected" ? "border-emerald-500/40 bg-emerald-500/5 text-emerald-700 dark:text-emerald-300" : aiState === "error" ? "border-destructive/40 text-destructive" : "text-muted-foreground"}`}>
            <span className="relative flex size-3 shrink-0">{aiState === "connected" && <span className="absolute inline-flex size-full animate-ping rounded-full bg-emerald-500/50 motion-reduce:animate-none" />}<span className={`relative inline-flex size-3 rounded-full ${aiState === "connected" ? "bg-emerald-500" : aiState === "error" ? "bg-destructive" : "bg-amber-500"}`} /></span>
            {aiMessage}
          </div>}
        </CardContent>
      </Card>

      <Card><CardContent className="space-y-5 p-5 md:p-6">
        <div><h2 className="flex items-center gap-2 font-semibold"><PlugZap className="size-4" /> Servidores MCP</h2><p className="mt-1 text-sm text-muted-foreground">Conecte fontes como Jira/Rovo e libere as ferramentas somente aos agentes escolhidos.</p></div>
        <div className="grid gap-3 md:grid-cols-[1fr_1.5fr_1fr_auto] md:items-end">
          <div className="space-y-2"><Label htmlFor="mcp-name">Identificador</Label><Input id="mcp-name" value={connectorName} onChange={(e) => setConnectorName(e.target.value)} /></div>
          <div className="space-y-2"><Label htmlFor="mcp-url">URL HTTPS do MCP</Label><Input id="mcp-url" value={connectorUrl} onChange={(e) => setConnectorUrl(e.target.value)} /></div>
          <div className="space-y-2"><Label htmlFor="mcp-token">Token, se habilitado</Label><Input id="mcp-token" type="password" autoComplete="off" value={connectorToken} onChange={(e) => setConnectorToken(e.target.value)} placeholder="Opcional" /></div>
          <Button variant="secondary" onClick={() => void saveConnector()} disabled={mcpBusy}>{mcpBusy ? <Loader2 className="animate-spin" /> : <PlugZap />} Salvar</Button>
        </div>
        <p className="text-xs text-muted-foreground">Rovo usa OAuth 2.1 por padrão. Token estático depende de habilitação pela administração Atlassian; sem isso, o teste mostrará falha e a conexão não será marcada como ativa.</p>
        <div className="space-y-3">
          {servers.map((server) => <div key={server.id} className="rounded-xl border p-4">
            <div className="flex flex-wrap items-start justify-between gap-2"><div><div className="flex items-center gap-2 font-medium">{server.name === "soc_demo_reports" ? "Relatórios de demonstração" : server.name.replaceAll("_", " ")}{server.name === "soc_demo_reports" && <Badge variant="outline">Exemplo</Badge>}</div><p className="mt-1 break-all text-xs text-muted-foreground">{server.url || `${server.command} ${(server.args || []).join(" ")}`}</p></div><Badge variant={server.last_connect_ok ? "default" : "outline"}>{server.last_connect_ok ? "Conectado" : server.last_connect_ok === false ? "Falha" : "Não testado"}</Badge></div>
            <div className="mt-3 flex flex-wrap items-center gap-2"><Button size="sm" variant="outline" onClick={() => void testConnector(server)} disabled={busyServer === server.id}>{busyServer === server.id ? <Loader2 className="animate-spin" /> : <RefreshCw />} Testar MCP</Button><span className="text-xs text-muted-foreground">{(tools[server.id] || []).length} ferramentas · {server.env_configured ? "credencial salva" : "sem credencial"}</span></div>
            {!!tools[server.id]?.length && <p className="mt-2 text-xs text-muted-foreground">{tools[server.id].slice(0, 5).map((t) => t.name.replace(/^mcp__.*?__/, "")).join(" · ")}{tools[server.id].length > 5 ? " · …" : ""}</p>}
            {!!agents.length && <div className="mt-3 flex flex-wrap items-center gap-2 border-t pt-3"><span className="mr-1 text-xs text-muted-foreground">Liberar para:</span>{agents.map((agent) => <button key={agent.id} type="button" onClick={() => void bindAgent(server, agent)} className={`rounded-full border px-2.5 py-1 text-xs ${visibility[server.id]?.includes(agent.id) ? "border-primary bg-primary/10 text-primary" : "text-muted-foreground"}`}>{visibility[server.id]?.includes(agent.id) && <CheckCircle2 className="mr-1 inline size-3" />}{agent.name}</button>)}</div>}
          </div>)}
        </div>
        <p className="text-xs text-muted-foreground">Ferramentas que criam ou alteram tarefas passam pelo agente e sua aprovação. <Link className="underline" href="/system/mcp">Configuração técnica avançada</Link></p>
      </CardContent></Card>

      {demo && <Card><CardContent className="space-y-4 p-5 md:p-6"><div className="flex flex-wrap items-center justify-between gap-3"><div><h2 className="flex items-center gap-2 font-semibold"><FileText className="size-4" /> Relatórios de demonstração</h2><p className="mt-1 text-sm text-muted-foreground">Dados fictícios servidos pelo MCP local, para testar leitura e download.</p></div><Button variant="outline" onClick={() => void listReports()} disabled={busyServer === demo.id}>Buscar relatórios</Button></div>
        {!!reports.length && <div className="grid gap-2 sm:grid-cols-2">{reports.map((report) => <button type="button" key={report.id} onClick={() => void openReport(report)} className="rounded-lg border p-3 text-left hover:bg-muted/50"><span className="block text-sm font-medium">{report.title}</span><span className="text-xs text-muted-foreground">{report.id} · Markdown fictício</span></button>)}</div>}
        {!!reportText && <div className="space-y-3"><pre className="max-h-72 overflow-auto rounded-lg border bg-muted/30 p-4 text-xs whitespace-pre-wrap">{reportText}</pre><Button onClick={downloadReport}><Download /> Baixar relatório .md</Button></div>}
      </CardContent></Card>}
    </div>
  );
}
