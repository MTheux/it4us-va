"use client";

import * as React from "react";
import Link from "next/link";
import { ArrowRightIcon, CheckCircle2Icon, CircleDashedIcon, Loader2Icon } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api } from "@/lib/api";
import type { Agent, VACapabilities, LLMProfile, MCPServer } from "@/lib/types";

type Format = "ollama" | "openai" | "openai-responses" | "anthropic";

const steps = [
  { number: "01", title: "Ativos e escopo", href: "/function/assets", action: "Abrir ativos", description: "Cadastre o ambiente e separe os ativos de cada cliente antes da avaliação." },
  { number: "02", title: "Campanha VA", href: "/function/va-runs", action: "Abrir execuções", description: "Informe os IPs ou ranges aprovados, revise o plano e acompanhe o discovery de portas e serviços." },
  { number: "03", title: "Investigação por agente", href: "/system/agents", action: "Configurar agentes", description: "Escolha o agente, o modelo e quais ferramentas MCP ele pode enxergar." },
  { number: "04", title: "Revisão do SOC", href: "/function/findings", action: "Abrir achados", description: "Revise os candidatos e só então encaminhe os achados confirmados." },
] as const;

export default function QuickstartPage() {
  const [profiles, setProfiles] = React.useState<LLMProfile[]>([]);
  const [mcp, setMcp] = React.useState<MCPServer[]>([]);
  const [agents, setAgents] = React.useState<Agent[]>([]);
  const [capabilities, setCapabilities] = React.useState<VACapabilities | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [busy, setBusy] = React.useState(false);
  const [feedback, setFeedback] = React.useState("");
  const [format, setFormat] = React.useState<Format>("ollama");
  const [model, setModel] = React.useState("");
  const [baseUrl, setBaseUrl] = React.useState("http://127.0.0.1:11434/v1");
  const [apiKey, setApiKey] = React.useState("");
  const [availableModels, setAvailableModels] = React.useState<string[]>([]);
  const [loadingModels, setLoadingModels] = React.useState(false);

  const refresh = React.useCallback(async () => {
    const results = await Promise.allSettled([api.llmProfiles(), api.mcpServers(), api.agents(), api.vaCapabilities()]);
    if (results[0].status === "fulfilled") setProfiles(results[0].value);
    if (results[1].status === "fulfilled") setMcp(results[1].value);
    if (results[2].status === "fulfilled") setAgents(results[2].value);
    if (results[3].status === "fulfilled") setCapabilities(results[3].value);
    setLoading(false);
  }, []);

  React.useEffect(() => { void refresh(); }, [refresh]);

  function changeFormat(next: Format) {
    setFormat(next);
    setBaseUrl(next === "ollama" ? "http://127.0.0.1:11434/v1" : "");
    setAvailableModels([]);
    setModel("");
    setFeedback("");
  }

  async function loadLocalModels() {
    setLoadingModels(true);
    setFeedback("");
    try {
      const result = await api.fetchLLMModels("ollama", baseUrl.trim(), "");
      if (!result.ok || !result.models?.length) {
        setAvailableModels([]);
        setFeedback(`Nenhum modelo Ollama disponível: ${result.error || "verifique o serviço no worker"}`);
        return;
      }
      setAvailableModels(result.models);
      if (!model.trim()) setModel(result.models.find((item) => !item.endsWith(":cloud")) || result.models[0]);
      setFeedback(`${result.models.length} modelo(s) encontrado(s) no Ollama.`);
    } catch (error) {
      setFeedback(`Não foi possível consultar o Ollama: ${error instanceof Error ? error.message : "erro desconhecido"}`);
    } finally {
      setLoadingModels(false);
    }
  }

  async function connectModel(event: React.FormEvent) {
    event.preventDefault();
    const chosenModel = model.trim();
    if (!chosenModel || (format !== "ollama" && !apiKey.trim())) {
      setFeedback("Informe o modelo e, para provedores externos, a chave de API.");
      return;
    }
    setBusy(true);
    setFeedback("Testando a conexão...");
    try {
      const result = await api.testLLM(format, chosenModel, baseUrl.trim(), apiKey.trim());
      if (!result.ok) {
        setFeedback(`Conexão não validada: ${result.error || "o modelo não respondeu"}`);
        return;
      }
      const saved = await api.saveLLMProfile({
        name: `SOC · ${chosenModel}`,
        format,
        model: chosenModel,
        base_url: baseUrl.trim(),
        api_key: apiKey.trim(),
      });
      await api.activateLLMProfile(String(saved.id));
      setApiKey("");
      setFeedback(`Modelo ${chosenModel} testado e ativado para os agentes.`);
      await refresh();
    } catch (error) {
      setFeedback(`Não foi possível concluir: ${error instanceof Error ? error.message : "erro desconhecido"}`);
    } finally {
      setBusy(false);
    }
  }

  const active = profiles.find((profile) => profile.is_default);
  const modelReady = !!active && (active.format === "ollama" || !!active.api_key_hint);
  const connectedMcp = mcp.filter((server) => server.enabled && server.last_connect_ok === true).length;
  const worker = agents.find((agent) => agent.key === "worker" && agent.enabled);

  return (
    <div className="mx-auto flex max-w-6xl flex-col gap-8 p-6 pb-16 md:p-10">
      <header className="space-y-3 border-b border-border pb-7">
        <p className="font-mono text-xs font-semibold uppercase tracking-[0.2em] text-primary">Guard4US / Primeiro acesso</p>
        <h1 className="text-3xl font-semibold tracking-tight md:text-4xl">Prepare a operação do SOC</h1>
        <p className="max-w-2xl text-sm leading-6 text-muted-foreground">
          O scanner executa discovery sem LLM. Ative um modelo e MCP se o SOC quiser investigação assistida por agente.
        </p>
      </header>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <Readiness title="Scanner" ready={!!capabilities?.scanner_available} detail={capabilities?.scanner_available ? capabilities.scanner : "Motor VA indisponível no worker"} loading={loading} />
        <Readiness title="LLM" ready={modelReady} optional={!active} detail={active ? `${active.name} · ${active.model}` : "Opcional para o discovery"} loading={loading} />
        <Readiness title="MCP" ready={connectedMcp > 0} optional={mcp.length === 0} detail={mcp.length ? `${connectedMcp} conectado(s) de ${mcp.length}` : "Opcional: nenhum servidor cadastrado"} loading={loading} />
        <Readiness title="Agente" ready={!!worker && modelReady} optional={!modelReady} detail={worker ? (modelReady ? "Worker com LLM configurado" : "Worker disponível; LLM opcional") : "Worker indisponível"} loading={loading} />
      </div>

      <Card className="border-primary/30 bg-card/90">
        <CardHeader><CardTitle className="text-xl">1. Scanner de infraestrutura</CardTitle></CardHeader>
        <CardContent className="flex flex-wrap items-center justify-between gap-4 text-sm text-muted-foreground">
          <p className="max-w-2xl">O Nmap roda no worker instalado na rede do cliente. Cadastre uma tarefa, valide o plano de IPs/ranges e portas, e inicie a campanha em Execuções VA.</p>
          <Button asChild><Link href="/function/va-runs">Abrir execuções <ArrowRightIcon className="size-4" /></Link></Button>
        </CardContent>
      </Card>

      <Card className="border-primary/30 bg-card/90">
        <CardHeader>
          <CardTitle className="text-xl">2. LLM para análise assistida <Badge variant="outline" className="ml-2 align-middle text-xs">Opcional</Badge></CardTitle>
          <p className="text-sm text-muted-foreground">O modelo não escolhe alvos nem flags do scanner. Se quiser assistência para investigar candidatos, teste a resposta e ative um perfil. A chave é enviada ao servidor somente ao testar e salvar.</p>
        </CardHeader>
        <CardContent>
          <form onSubmit={connectModel} className="grid gap-4 lg:grid-cols-[1fr_1fr]">
            <div className="space-y-2">
              <Label htmlFor="provider">Provedor</Label>
              <select id="provider" className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm focus-visible:outline-2 focus-visible:outline-primary" value={format} onChange={(event) => changeFormat(event.target.value as Format)}>
                <option value="ollama">Ollama local</option>
                <option value="openai-responses">OpenAI Responses</option>
                <option value="openai">OpenAI compatível</option>
                <option value="anthropic">Anthropic</option>
              </select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="model">Modelo</Label>
              <Input id="model" value={model} onChange={(event) => setModel(event.target.value)} placeholder={format === "ollama" ? "Ex.: modelo instalado no Ollama" : "Nome exato do modelo"} autoComplete="off" />
              {format === "ollama" && <div className="flex flex-wrap items-center gap-2"><Button type="button" variant="outline" size="sm" disabled={loadingModels} onClick={() => void loadLocalModels()}>{loadingModels && <Loader2Icon className="size-3 animate-spin" />} Buscar modelos locais</Button>{availableModels.length > 0 && <select aria-label="Selecionar modelo Ollama" className="h-8 min-w-0 flex-1 rounded-md border border-input bg-background px-2 text-xs" value={model} onChange={(event) => setModel(event.target.value)}><option value="">Selecione um modelo</option>{availableModels.map((item) => <option key={item} value={item}>{item}</option>)}</select>}</div>}
            </div>
            <div className="space-y-2">
              <Label htmlFor="base-url">URL do serviço {format === "ollama" ? "local" : "(opcional)"}</Label>
              <Input id="base-url" type="url" value={baseUrl} onChange={(event) => setBaseUrl(event.target.value)} placeholder="Padrão do provedor" autoComplete="off" />
            </div>
            <div className="space-y-2">
              <Label htmlFor="api-key">Chave de API {format === "ollama" ? "(não necessária)" : ""}</Label>
              <Input id="api-key" type="password" value={apiKey} onChange={(event) => setApiKey(event.target.value)} disabled={format === "ollama"} autoComplete="off" placeholder={format === "ollama" ? "Sem chave" : "Cole a chave aqui"} />
            </div>
            <div className="flex flex-wrap items-center gap-3 lg:col-span-2">
              <Button type="submit" disabled={busy}>{busy && <Loader2Icon className="size-4 animate-spin" />} Testar e ativar</Button>
              <Button variant="outline" asChild><Link href="/system/llm">Configuração avançada <ArrowRightIcon className="size-4" /></Link></Button>
              {feedback && <p role="status" className="text-sm text-muted-foreground">{feedback}</p>}
            </div>
          </form>
        </CardContent>
      </Card>

      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader><CardTitle className="text-xl">3. Conecte ferramentas MCP</CardTitle></CardHeader>
          <CardContent className="space-y-4 text-sm text-muted-foreground">
            <p>Adicione os servidores necessários, teste a conexão e escolha a visibilidade de cada agente. MCP é opcional para começar.</p>
            <Button variant="outline" asChild><Link href="/system/mcp">Configurar MCP <ArrowRightIcon className="size-4" /></Link></Button>
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle className="text-xl">4. Prepare os agentes</CardTitle></CardHeader>
          <CardContent className="space-y-4 text-sm text-muted-foreground">
            <p>O Worker já vem com a instalação. Para análise assistida, vincule o perfil LLM e escolha as ferramentas MCP disponíveis.</p>
            <Button variant="outline" asChild><Link href="/system/agents">Configurar agentes <ArrowRightIcon className="size-4" /></Link></Button>
          </CardContent>
        </Card>
      </div>

      <section className="space-y-4">
        <div><p className="font-mono text-xs uppercase tracking-[0.2em] text-primary">Fluxo de avaliação</p><h2 className="mt-2 text-2xl font-semibold">Do escopo à revisão</h2></div>
        <div className="grid gap-3 md:grid-cols-2">
          {steps.map((step) => (
            <Link key={step.number} href={step.href} className="group rounded-xl border border-border bg-card p-5 transition-colors hover:border-primary/50 hover:bg-accent/30">
              <span className="font-mono text-xs text-primary">{step.number}</span>
              <h3 className="mt-2 flex items-center justify-between font-semibold">{step.title}<ArrowRightIcon className="size-4 transition-transform group-hover:translate-x-1" /></h3>
              <p className="mt-2 text-sm leading-6 text-muted-foreground">{step.description}</p>
              <span className="mt-4 inline-block text-xs font-medium text-primary">{step.action}</span>
            </Link>
          ))}
        </div>
      </section>
    </div>
  );
}

function Readiness({ title, ready, optional = false, detail, loading }: { title: string; ready: boolean; optional?: boolean; detail: string; loading: boolean }) {
  return (
    <Card className="bg-card/75">
      <CardContent className="flex items-start justify-between gap-3 pt-5">
        <div><p className="text-sm font-semibold">{title}</p><p className="mt-1 text-xs text-muted-foreground">{loading ? "Verificando..." : detail}</p></div>
        <Badge variant="outline" className={ready ? "border-primary/40 text-primary" : "border-border text-muted-foreground"}>
          {ready ? <CheckCircle2Icon className="mr-1 size-3" /> : <CircleDashedIcon className="mr-1 size-3" />}
          {ready ? "Configurado" : optional ? "Opcional" : "Pendente"}
        </Badge>
      </CardContent>
    </Card>
  );
}
