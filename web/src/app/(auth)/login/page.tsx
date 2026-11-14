"use client";

import { useEffect, useRef, useState } from "react";

import { useRouter } from "next/navigation";

import { AlertTriangle, Eye, EyeOff, LockKeyhole, ShieldCheck } from "lucide-react";
import { QRCodeSVG } from "qrcode.react";

import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogClose, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api } from "@/lib/api";
import { auth } from "@/lib/auth";
import styles from "./login.module.css";

export default function LoginPage() {
  const router = useRouter();
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [mfaEnabled, setMfaEnabled] = useState(false);
  const [stage, setStage] = useState<"login" | "enroll" | "recovery">("login");
  const [setupToken, setSetupToken] = useState("");
  const [mfaSecret, setMfaSecret] = useState("");
  const [mfaURI, setMfaURI] = useState("");
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [checking, setChecking] = useState(true);
  const [agreed, setAgreed] = useState(false);
  const [termsOpen, setTermsOpen] = useState(false);
  const [readToEnd, setReadToEnd] = useState(false);
  const termsBodyRef = useRef<HTMLDivElement>(null);

  // Scroll to the bottom of the terms (including when everything fits without scrolling) to unlock "Agree".
  function handleTermsScroll() {
    const el = termsBodyRef.current;
    if (!el) return;
    if (el.scrollTop + el.clientHeight >= el.scrollHeight - 8) setReadToEnd(true);
  }

  useEffect(() => {
    if (!termsOpen) return;
    // Reset on open, and cover the case where the content is shorter than one screen and never fires a scroll.
    setReadToEnd(false);
    const el = termsBodyRef.current;
    if (el && el.scrollHeight <= el.clientHeight + 8) setReadToEnd(true);
  }, [termsOpen]);

  useEffect(() => {
    async function check() {
      const token = auth.getToken();
      if (token) {
        try {
          await api.authSession();
          auth.setToken(token);
          window.location.replace("/function/va-runs");
          return;
        } catch { auth.clearToken(); }
      }
      try {
        const status = await api.authStatus();
        if (!status.initialized) router.replace("/setup");
        setMfaEnabled(status.mfa_enabled);
      } catch { setError("Não foi possível conectar ao servidor"); }
      finally { setChecking(false); }
    }
    void check();
  }, [router]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!agreed) {
      setError("Leia e aceite os Termos de Uso primeiro");
      return;
    }
    setLoading(true);
    setError("");
    try {
      const result = await api.login("IT4US VA", password, code);
      if (result.mfa_setup && result.setup_token) {
        const enrollment = await api.mfaSetup(result.setup_token);
        setSetupToken(result.setup_token);
        setMfaSecret(enrollment.secret);
        setMfaURI(enrollment.uri);
        setCode("");
        setStage("enroll");
      } else if (result.token) {
        auth.setToken(result.token);
        window.location.replace("/function/va-runs");
      } else { setError("Resposta de autenticação inválida."); }
    } catch {
      setError("Credenciais ou código MFA inválidos. Confira e tente novamente.");
    } finally {
      setLoading(false);
    }
  }

  async function confirmMFA(e: React.FormEvent) {
    e.preventDefault();
    if (!setupToken || !code) return;
    setLoading(true); setError("");
    try {
      const result = await api.mfaConfirm(setupToken, code);
      auth.setToken(result.token);
      setRecoveryCodes(result.recovery_codes);
      setMfaSecret(""); setMfaURI(""); setSetupToken(""); setCode(""); setPassword("");
      setStage("recovery");
    } catch { setError("Código inválido ou configuração expirada. Reinicie o login se necessário."); }
    finally { setLoading(false); }
  }

  if (checking) {
    return (
      <div role="status" className="flex min-h-dvh items-center justify-center text-muted-foreground">
        Verificando sessão…
      </div>
    );
  }

  return (
    <main className={styles.shell}>
      <div className={styles.grid} aria-hidden="true" />
      <div className={styles.dots} aria-hidden="true" />
      <div className={styles.loginWrap}>
        <div className={styles.brand}>
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img src="/brand/it4us-icon.svg" alt="" width={34} height={34} />
          <span>GUARD<strong>4US</strong></span>
        </div>
        <div className={styles.card}>
          <div className={styles.cardHeading}>
            <div className={styles.eyebrow}><span /> Acesso ao ambiente</div>
            <h1>{stage === "enroll" ? "Ative a verificação em duas etapas" : stage === "recovery" ? "Guarde seus códigos" : "Bem-vindo de volta"}</h1>
            <p>{stage === "enroll" ? "Adicione o Guard4US ao aplicativo autenticador e confirme o código." : stage === "recovery" ? "Estes códigos aparecem uma vez e permitem recuperar o acesso." : "Entre para acompanhar suas análises de infraestrutura."}</p>
          </div>
          {stage === "login" ?
          <form onSubmit={handleSubmit} className={styles.form}>
            <div className={styles.field}>
              <Label htmlFor="account">Conta</Label>
              <div className={styles.account} id="account" aria-label="Conta Guard4US">
                <LockKeyhole size={16} aria-hidden="true" /> Equipe IT4US
              </div>
            </div>
            {mfaEnabled && <div className={styles.field}>
              <Label htmlFor="mfa-code">Código MFA ou recuperação</Label>
              <Input id="mfa-code" value={code} onChange={(event) => setCode(event.target.value)} placeholder="000000 ou código de recuperação" autoComplete="one-time-code" inputMode="text" maxLength={20} className={styles.passwordInput} />
            </div>}
            <div className={styles.field}>
              <Label htmlFor="password">Senha</Label>
              <div className={styles.passwordRow}>
                <Input
                  id="password"
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Digite sua senha"
                  autoComplete="current-password"
                  className={styles.passwordInput}
                />
                <button type="button" className={styles.visibility} onClick={() => setShowPassword(!showPassword)} aria-label={showPassword ? "Ocultar senha" : "Mostrar senha"}>
                  {showPassword ? <EyeOff size={17} /> : <Eye size={17} />}
                </button>
              </div>
            </div>
            <div className={styles.terms}>
              <Checkbox id="agree-terms" checked={agreed} onCheckedChange={(v) => setAgreed(v === true)} />
              <Label htmlFor="agree-terms">
                Li e concordo com os{" "}
                <button type="button" onClick={() => setTermsOpen(true)}>Termos de Uso</button>
              </Label>
            </div>
            {error && <p role="alert" className={styles.error}>{error}</p>}
            <Button type="submit" className={styles.submit} disabled={loading || !password || !agreed || (mfaEnabled && !code.trim())}>
              {loading ? "Entrando..." : "Entrar na plataforma"}
            </Button>
          </form>
          : stage === "enroll" ? <form onSubmit={confirmMFA} className={styles.form}>
            <div className={styles.qr}><QRCodeSVG value={mfaURI} size={176} marginSize={2} /></div>
            <p className={styles.helper}>Se não conseguir ler o QR, digite esta chave no autenticador:</p>
            <code className={styles.secret}>{mfaSecret}</code>
            <div className={styles.field}><Label htmlFor="enroll-code">Código de 6 dígitos</Label><Input id="enroll-code" value={code} onChange={(event) => setCode(event.target.value.replace(/\D/g, "").slice(0, 6))} inputMode="numeric" autoComplete="one-time-code" maxLength={6} placeholder="000000" className={styles.passwordInput} /></div>
            {error && <p role="alert" className={styles.error}>{error}</p>}
            <Button type="submit" className={styles.submit} disabled={loading || code.length !== 6}>{loading ? "Confirmando..." : "Ativar MFA"}</Button>
          </form> : <div className={styles.form}>
            <div className={styles.recoveryList}>{recoveryCodes.map((item) => <code key={item}>{item}</code>)}</div>
            <p className={styles.helper}>Salve estes códigos em um cofre. Cada código funciona uma única vez.</p>
            <Button className={styles.submit} onClick={() => window.location.replace("/function/va-runs")}>Guardei os códigos · continuar</Button>
          </div>}
        </div>
        <p className={styles.footer}>ACESSO RESTRITO À EQUIPE AUTORIZADA</p>
      </div>

      <Dialog open={termsOpen} onOpenChange={setTermsOpen}>
        <DialogContent className="gap-0 p-0 sm:max-w-2xl">
          <DialogHeader className="flex-row items-center gap-3 border-b px-6 py-4">
            <div className="flex size-10 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary">
              <ShieldCheck className="size-5" />
            </div>
            <div className="space-y-0.5">
              <DialogTitle className="text-base">Termos de Uso e Isenção de Responsabilidade do Guard4US</DialogTitle>
              <p className="text-xs text-muted-foreground">
                Version v1.1 · Effective 2026-10-11 · Please read all the following terms in full before signing in
              </p>
            </div>
          </DialogHeader>

          <div
            ref={termsBodyRef}
            onScroll={handleTermsScroll}
            className="max-h-[60vh] space-y-5 overflow-y-auto px-6 py-5 text-sm leading-relaxed text-muted-foreground"
          >
            <p className="rounded-lg border bg-muted/40 p-3 text-foreground/80">
              This Terms of Use and Disclaimer (the "Statement") is the agreement between you and the IT4US VA project
              authors and contributors regarding your use of this software. Please read it carefully and fully
              understand each provision before use, especially the disclaimer, liability-limitation, and prohibition
              clauses highlighted in bold or color blocks.
              <span className="font-medium text-foreground">
                {" "}
                Once you download, install, access, or use this software in any way, you are deemed to have read,
                understood, and agreed to be bound by all of this Statement.
              </span>
            </p>

            <section className="space-y-1.5">
              <h4 className="flex items-center gap-2 font-medium text-foreground">
                <span className="flex size-5 items-center justify-center rounded-md bg-muted text-xs font-semibold text-muted-foreground">
                  1
                </span>
                Article 1 · Definitions and Open-Source License
              </h4>
              <p className="pl-7">
                This software (IT4US VA) is an open-source program released under the GNU Affero General Public License
                v3.0 (AGPL-3.0). You may freely use, copy, modify, and distribute it under that license; however, any
                derivative work (including online services provided to third parties over a network) must likewise be
                open-sourced under the AGPL-3.0 license with the complete corresponding source code made public to its
                users. The full AGPL-3.0 terms are governed by the accompanying LICENSE file.
              </p>
            </section>

            <section className="space-y-1.5">
              <h4 className="flex items-center gap-2 font-medium text-foreground">
                <span className="flex size-5 items-center justify-center rounded-md bg-muted text-xs font-semibold text-muted-foreground">
                  2
                </span>
                Article 2 · Permitted Scope of Use
              </h4>
              <p className="pl-7">
                This software is a security-testing platform. You may use it for: personal study, code research, and
                technical verification in environments you set up yourself; security testing of systems you own;
                security testing of third-party systems when you hold the owner's explicit authorization; and testing
                within the written scope of a bug bounty or vulnerability disclosure program, in compliance with that
                program's rules of engagement. You are responsible for obtaining and keeping proof of authorization, for
                staying inside the authorized scope, and for the safety and proportionality of every action the software
                takes on your behalf.
              </p>
            </section>

            <section className="space-y-2">
              <h4 className="flex items-center gap-2 font-medium text-destructive">
                <span className="flex size-5 items-center justify-center rounded-md bg-destructive/10 text-xs font-semibold text-destructive">
                  3
                </span>
                <AlertTriangle className="size-4" />
                Article 3 · Prohibited Conduct
              </h4>
              <ul className="ml-7 list-decimal space-y-1.5 rounded-lg border border-destructive/20 bg-destructive/5 p-3 pl-8 text-foreground/80 marker:text-destructive/70">
                <li>
                  Strictly forbidden: scanning, probing, exploiting, or attacking any system whose owner has not
                  explicitly authorized you to test it, or exceeding the authorized scope or a program's rules of
                  engagement once granted;
                </li>
                <li>
                  Strictly forbidden: using this software for illegal intrusion, data theft, extortion, denial of
                  service (DoS/DDoS), or any destructive or criminal activity;
                </li>
                <li>
                  Strictly forbidden: removing, tampering with, or circumventing any copyright, license, or security
                  notice in this software or its output;
                </li>
                <li>
                  Strictly forbidden: engaging in any conduct that violates the laws, regulations, or regulatory rules
                  of your country or region.
                </li>
              </ul>
            </section>

            <section className="space-y-1.5">
              <h4 className="flex items-center gap-2 font-medium text-foreground">
                <span className="flex size-5 items-center justify-center rounded-md bg-muted text-xs font-semibold text-muted-foreground">
                  4
                </span>
                Article 4 · Intellectual Property
              </h4>
              <p className="pl-7">
                The copyright and related intellectual property of this software belong to the project authors and
                contributors, who grant you the corresponding rights within the scope of the AGPL-3.0 license. Beyond
                the rights expressly granted by that license, this Statement grants you no other rights, expressly or by
                implication.
              </p>
            </section>

            <section className="space-y-1.5">
              <h4 className="flex items-center gap-2 font-medium text-foreground">
                <span className="flex size-5 items-center justify-center rounded-md bg-muted text-xs font-semibold text-muted-foreground">
                  5
                </span>
                Article 5 · Data and Privacy
              </h4>
              <p className="pl-7">
                This software is a self-deployable open-source program; the authors run no centralized service and
                neither collect nor upload your usage data. All data you generate, process, or touch while using it
                stays under your control, and you are responsible for its legality and security; any consequence of
                improper data handling is yours to bear.
              </p>
            </section>

            <section className="space-y-1.5">
              <h4 className="flex items-center gap-2 font-medium text-foreground">
                <span className="flex size-5 items-center justify-center rounded-md bg-muted text-xs font-semibold text-muted-foreground">
                  6
                </span>
                Article 6 · Compliance and Legal Liability
              </h4>
              <p className="pl-7">
                You must comply on your own with all laws and regulations of your country or region on cybersecurity,
                data security and personal-information protection, computer crime, and the like (for example, laws on
                unauthorized access to computer systems, on personal-data protection, and on the responsibilities of
                security researchers and penetration testers in your jurisdiction).
                <span className="font-medium text-foreground">
                  {" "}
                  All legal liability and consequences arising from your violation of the above laws and regulations or
                  of this Statement are borne by you alone and have nothing to do with this software's authors and
                  contributors.
                </span>
              </p>
            </section>

            <section className="space-y-1.5">
              <h4 className="flex items-center gap-2 font-medium text-foreground">
                <span className="flex size-5 items-center justify-center rounded-md bg-muted text-xs font-semibold text-muted-foreground">
                  7
                </span>
                Article 7 · Disclaimer and Limitation of Liability
              </h4>
              <p className="pl-7">
                This software is provided on an "AS IS" and "AS AVAILABLE" basis, without any express or implied
                warranty, including but not limited to warranties of merchantability, fitness for a particular purpose,
                accuracy, and non-infringement. To the maximum extent permitted by applicable law, this software's
                authors and contributors are not liable for any direct, indirect, incidental, special, or consequential
                loss arising from using or being unable to use this software (regardless of whether it is used
                properly), including but not limited to data loss, system damage, business interruption, loss of profit,
                or legal disputes.
              </p>
            </section>

            <section className="space-y-1.5">
              <h4 className="flex items-center gap-2 font-medium text-foreground">
                <span className="flex size-5 items-center justify-center rounded-md bg-muted text-xs font-semibold text-muted-foreground">
                  8
                </span>
                Article 8 · Changes to the Terms and Final Interpretation
              </h4>
              <p className="pl-7">
                The authors may update this Statement from time to time as laws, regulations, or project development
                require; the updated version ships with the project and takes effect on its publication date, and your
                continued use of this software means you accept the revised terms. To the extent permitted by law, the
                authors hold the final right of interpretation of this Statement. If any provision of this Statement is
                held invalid, the remaining provisions stay in effect.
              </p>
            </section>
          </div>

          <DialogFooter className="mx-0 mb-0 flex-col items-stretch gap-2 rounded-b-xl px-6 sm:flex-row sm:items-center sm:justify-between">
            <p className="text-xs text-muted-foreground">
              {readToEnd ? "You have read all the terms" : "Scroll the terms to the bottom to confirm"}
            </p>
            <DialogClose asChild>
              <Button
                type="button"
                disabled={!readToEnd}
                onClick={() => {
                  setAgreed(true);
                  setError("");
                }}
              >
                I have read and agree to all the terms
              </Button>
            </DialogClose>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </main>
  );
}
