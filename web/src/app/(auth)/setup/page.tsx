"use client";

import { useEffect, useState } from "react";

import { useRouter } from "next/navigation";

import { DraxenCore } from "@/components/draxen-core";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api } from "@/lib/api";
import { auth } from "@/lib/auth";

export default function SetupPage() {
  const router = useRouter();
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [checking, setChecking] = useState(true);
  // when the initialization state cannot be fetched, do not default to "not initialized" — that would show the setup form to an
  // instance that already has a password, and following it would overwrite the original. Close the entrance instead.
  const [unavailable, setUnavailable] = useState(false);

  useEffect(() => {
    api
      .authStatus()
      .then(({ initialized }) => {
        if (initialized) router.replace("/login");
      })
      .catch((err) => {
        setError(err instanceof Error ? err.message : "Unable to connect to the backend service");
        setUnavailable(true);
      })
      .finally(() => setChecking(false));
  }, [router]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (password !== confirm) {
      setError("The two passwords do not match");
      return;
    }
    if (password.length < 8) {
      setError("Password must be at least 8 characters");
      return;
    }
    setLoading(true);
    setError("");
    try {
      const { token } = await api.initPassword(password);
      auth.setToken(token);
      router.replace("/function/tasks");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Initialization failed");
    } finally {
      setLoading(false);
    }
  }

  if (checking) return null;

  return (
    <div className="flex h-dvh">
      {/* Left panel — Draxen Core proof */}
      <div className="proof hidden flex-col justify-between gap-6 p-12 text-left lg:flex lg:w-1/2">
        <div className="proof-grid" aria-hidden="true" />
        <div className="proof-glow" aria-hidden="true" />
        <div className="relative space-y-4">
          <div className="proof-kicker">SEGURANÇA OFENSIVA · WEB &amp; API</div>
          <h1 className="proof-title">
            Fortaleça
            <br />
            sua <span className="accent">operação.</span>
          </h1>
          <p className="proof-copy">
            Seu workspace para transformar testes autorizados em evidências claras e decisões de correção.
          </p>
        </div>
        <div className="core-frame relative">
          <div className="core-frame-label">
            <span>DRAXEN CORE</span>
            <span>ASCII / VISUAL</span>
          </div>
          <DraxenCore className="core-canvas" />
          <div className="core-frame-label">
            <span>ESCOPO → EVIDÊNCIA → CORREÇÃO</span>
            <span>LIVE</span>
          </div>
        </div>
        <div className="proof-bottom">
          A precisão de uma operação Red Team.
          <br />
          <strong>A clareza que sua equipe precisa para agir.</strong>
        </div>
      </div>

      {/* Right panel */}
      <div className="flex w-full items-center justify-center bg-background p-8 lg:w-1/2">
        <div className="w-full max-w-md space-y-10 py-24 lg:py-32">
          <div className="space-y-4 text-center">
            <h2 className="text-2xl font-medium tracking-tight">{unavailable ? "Não foi possível confirmar o estado de inicialização" : "Defina a senha inicial"}</h2>
            <p className="mx-auto max-w-xl text-muted-foreground">
              {unavailable
                ? "O backend ou o banco de dados está temporariamente indisponível. Para evitar sobrescrever uma senha já definida nesta instância, a configuração foi temporariamente bloqueada — restaure o serviço e tente novamente."
                : "Primeira vez usando o Draxen? Defina uma senha de login para a conta (no mínimo 8 caracteres)"}
            </p>
          </div>
          {unavailable ? (
            <div className="flex flex-col gap-4">
              {error && <p className="text-center text-sm text-destructive">{error}</p>}
              <Button type="button" className="w-full" onClick={() => window.location.reload()}>Tentar novamente</Button>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="flex flex-col gap-4">
              <div className="space-y-1.5">
                <Label htmlFor="password">Nova senha</Label>
                <Input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="No mínimo 8 caracteres"
                  autoFocus
                  autoComplete="new-password"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="confirm">Confirmar senha</Label>
                <Input
                  id="confirm"
                  type="password"
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                  placeholder="Digite a senha novamente"
                  autoComplete="new-password"
                />
              </div>
              {error && <p className="text-sm text-destructive">{error}</p>}
              <Button type="submit" className="w-full" disabled={loading || !password || !confirm}>
                {loading ? "Salvando..." : "Definir senha e entrar"}
              </Button>
            </form>
          )}
        </div>
      </div>
    </div>
  );
}
