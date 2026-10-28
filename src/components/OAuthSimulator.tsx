import { useEffect, useMemo, useRef, useState } from "react";
import {
  Play,
  RotateCcw,
  StepForward,
  Check,
  Globe,
  UserCheck,
  ArrowLeftRight,
  Server,
  Copy,
  ChevronRight,
  ShieldCheck,
  Lock,
  Unlock,
  Fingerprint,
  Terminal,
  ExternalLink,
  Ban,
} from "lucide-react";
import { base64UrlEncode, randomBase64Url } from "../utils/jwt";
import { cn } from "../utils/cn";

const SCOPES = [
  { id: "openid", label: "openid", desc: "OIDC identity", required: true },
  { id: "profile", label: "profile", desc: "Name & avatar", required: false },
  { id: "email", label: "email", desc: "Email address", required: false },
  { id: "offline_access", label: "offline_access", desc: "Refresh tokens", required: false },
  { id: "admin:read", label: "admin:read", desc: "Admin scope", required: false },
  { id: "billing:read", label: "billing:read", desc: "Billing scope", required: false },
];

type Phase = "idle" | "redirect" | "consent" | "exchange" | "resource" | "done" | "denied";

interface LogLine {
  t: string;
  actor: string;
  msg: string;
  tone: "info" | "ok" | "warn" | "req" | "res";
}

const STEPS = [
  { n: 1, id: "redirect", title: "Redirect to Auth Server", desc: "Client builds /authorize URL with PKCE challenge + state", icon: Globe },
  { n: 2, id: "consent", title: "Grant Consent", desc: "User authenticates & approves requested scopes", icon: UserCheck },
  { n: 3, id: "exchange", title: "Exchange Code for Tokens", desc: "POST /token with code + verifier → ID + access tokens", icon: ArrowLeftRight },
  { n: 4, id: "resource", title: "Access Protected Resource", desc: "Call API with Bearer access token", icon: Server },
];

export default function OAuthSimulator({ issuer, onUseToken }: { issuer: string; onUseToken: (t: string) => void }) {
  const [clientId, setClientId] = useState("authpulse-demo-client");
  const [redirectUri, setRedirectUri] = useState("https://app.authpulse.dev/callback");
  const [scopes, setScopes] = useState<string[]>(["openid", "profile", "email"]);
  const [usePkce, setUsePkce] = useState(true);
  const [phase, setPhase] = useState<Phase>("idle");
  const [autoPlaying, setAutoPlaying] = useState(false);
  const [logs, setLogs] = useState<LogLine[]>([]);
  const [copied, setCopied] = useState<string | null>(null);
  const logRef = useRef<HTMLDivElement>(null);

  const flow = useMemo(() => {
    const state = randomBase64Url(16);
    const verifier = randomBase64Url(48);
    const challenge = base64UrlEncode(verifier).slice(0, 43);
    const code = "auth_" + randomBase64Url(24);
    const now = Math.floor(Date.now() / 1000);
    const mkJwt = (payload: object) =>
      `${base64UrlEncode(JSON.stringify({ alg: "RS256", typ: "JWT", kid: "prod-rsa-2025-11" }))}.${base64UrlEncode(JSON.stringify(payload))}.${randomBase64Url(64)}`;
    const accessToken = mkJwt({
      sub: "usr_9f3a2b1c", iss: issuer, aud: "authpulse-api",
      iat: now, exp: now + 3600, scope: scopes.join(" "), client_id: clientId,
    });
    const idToken = mkJwt({
      sub: "usr_9f3a2b1c", name: "Maya Chen", email: "maya.chen@authpulse.dev",
      iss: issuer, aud: clientId, iat: now, exp: now + 3600,
      auth_time: now, acr: "urn:authpulse:acr:mfa", nonce: randomBase64Url(12),
    });
    return { state, verifier, challenge, code, accessToken, idToken, refreshToken: "rt_" + randomBase64Url(32) };
  }, [clientId, scopes, issuer]);

  const authUrl = `${issuer}/authorize?response_type=code&client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(redirectUri)}&scope=${encodeURIComponent(scopes.join(" "))}&state=${flow.state}${usePkce ? `&code_challenge=${flow.challenge}&code_challenge_method=S256` : ""}`;

  const pushLog = (actor: string, msg: string, tone: LogLine["tone"] = "info") => {
    const t = new Date().toLocaleTimeString("en-US", { hour12: false });
    setLogs((l) => [...l, { t, actor, msg, tone }]);
  };

  useEffect(() => {
    logRef.current?.scrollTo({ top: logRef.current.scrollHeight, behavior: "smooth" });
  }, [logs]);

  const reset = () => {
    setPhase("idle");
    setLogs([]);
    setAutoPlaying(false);
  };

  const stepTo = (p: Phase) => {
    if (p === "redirect") {
      setPhase("redirect");
      pushLog("CLIENT", `GET ${issuer}/authorize — response_type=code, ${scopes.length} scopes`, "req");
      pushLog("CLIENT", `PKCE challenge (S256): ${flow.challenge.slice(0, 18)}… · state: ${flow.state.slice(0, 12)}…`, "info");
    } else if (p === "consent") {
      setPhase("consent");
      pushLog("AUTH SERVER", "Session cookie found — user already authenticated (SSO). Rendering consent screen.", "res");
    } else if (p === "exchange") {
      setPhase("exchange");
      pushLog("AUTH SERVER", `302 → ${redirectUri}?code=${flow.code.slice(0, 16)}…&state=${flow.state.slice(0, 10)}…`, "res");
      pushLog("CLIENT", `POST ${issuer}/token — grant_type=authorization_code + code_verifier`, "req");
      setTimeout(() => {
        pushLog("AUTH SERVER", "200 OK — code verified, PKCE challenge matched. Issuing token set.", "ok");
      }, 600);
    } else if (p === "resource") {
      setPhase("resource");
      pushLog("CLIENT", "GET https://api.authpulse.dev/v1/me — Authorization: Bearer eyJ…", "req");
      setTimeout(() => {
        pushLog("RESOURCE API", "200 OK — signature valid, scope sufficient. Returning profile.", "ok");
      }, 600);
    } else if (p === "done") {
      setPhase("done");
      pushLog("CLIENT", "Flow complete — tokens stored in memory. Session established.", "ok");
    }
  };

  const next = () => {
    if (phase === "idle") stepTo("redirect");
    else if (phase === "redirect") stepTo("consent");
    else if (phase === "consent") stepTo("exchange"); // approve
    else if (phase === "exchange") stepTo("resource");
    else if (phase === "resource") stepTo("done");
  };

  const deny = () => {
    setPhase("denied");
    pushLog("USER", "Consent denied — error=access_denied returned to client.", "warn");
  };

  // autoplay
  useEffect(() => {
    if (!autoPlaying) return;
    if (phase === "idle") {
      const t = setTimeout(() => stepTo("redirect"), 400);
      return () => clearTimeout(t);
    }
    if (phase === "redirect") {
      const t = setTimeout(() => stepTo("consent"), 1400);
      return () => clearTimeout(t);
    }
    if (phase === "consent") {
      const t = setTimeout(() => stepTo("exchange"), 1600);
      return () => clearTimeout(t);
    }
    if (phase === "exchange") {
      const t = setTimeout(() => stepTo("resource"), 1800);
      return () => clearTimeout(t);
    }
    if (phase === "resource") {
      const t = setTimeout(() => {
        stepTo("done");
        setAutoPlaying(false);
      }, 1800);
      return () => clearTimeout(t);
    }
  }, [autoPlaying, phase]);

  const phaseIndex = phase === "idle" ? -1 : phase === "redirect" ? 0 : phase === "consent" ? 1 : phase === "exchange" ? 2 : phase === "resource" || phase === "done" ? 3 : -1;

  const toggleScope = (id: string) => {
    const s = SCOPES.find((x) => x.id === id);
    if (s?.required) return;
    setScopes((prev) => (prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]));
    reset();
  };

  const copy = async (text: string, id: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(id);
      setTimeout(() => setCopied(null), 1500);
    } catch {}
  };

  return (
    <div className="grid gap-4 xl:grid-cols-[340px_1fr]">
      {/* Config panel */}
      <div className="card h-fit overflow-hidden">
        <div className="border-b border-white/[0.06] px-4 py-3">
          <h3 className="flex items-center gap-2 text-[13.5px] font-bold text-white">
            <Lock size={15} className="text-indigo-400" /> Client Configuration
          </h3>
          <p className="font-mono text-[10.5px] text-slate-500">authorization code + PKCE (OIDC)</p>
        </div>
        <div className="space-y-3.5 p-4">
          <div>
            <label className="mb-1.5 block text-[11px] font-bold uppercase tracking-widest text-slate-500">Client ID</label>
            <input value={clientId} onChange={(e) => { setClientId(e.target.value); reset(); }}
              className="w-full rounded-xl border border-white/10 bg-[#070b18] px-3 py-2.5 font-mono text-[12.5px] text-white outline-none focus:border-indigo-500/60 focus:ring-2 focus:ring-indigo-500/20" />
          </div>
          <div>
            <label className="mb-1.5 block text-[11px] font-bold uppercase tracking-widest text-slate-500">Redirect URI</label>
            <input value={redirectUri} onChange={(e) => { setRedirectUri(e.target.value); reset(); }}
              className="w-full rounded-xl border border-white/10 bg-[#070b18] px-3 py-2.5 font-mono text-[12px] text-white outline-none focus:border-indigo-500/60 focus:ring-2 focus:ring-indigo-500/20" />
          </div>
          <div>
            <label className="mb-1.5 block text-[11px] font-bold uppercase tracking-widest text-slate-500">
              Scopes <span className="ml-1 text-slate-600">· {scopes.length} selected</span>
            </label>
            <div className="flex flex-wrap gap-1.5">
              {SCOPES.map((s) => {
                const on = scopes.includes(s.id);
                return (
                  <button key={s.id} onClick={() => toggleScope(s.id)} title={s.desc}
                    className={cn(
                      "flex items-center gap-1 rounded-lg border px-2 py-1.5 font-mono text-[11.5px] transition-all",
                      on ? "border-indigo-500/50 bg-indigo-500/15 text-indigo-200" : "border-white/10 bg-white/[0.03] text-slate-500 hover:border-white/20",
                      s.required && "cursor-not-allowed opacity-80"
                    )}>
                    {on && <Check size={11} />}
                    {s.label}
                    {s.required && <span className="text-[9px] text-slate-500">req</span>}
                  </button>
                );
              })}
            </div>
          </div>
          <div className="flex items-center justify-between rounded-xl border border-white/[0.07] bg-[#070b18] px-3 py-2.5">
            <div>
              <div className="text-[12.5px] font-bold text-white">PKCE (S256)</div>
              <div className="font-mono text-[10.5px] text-slate-500">public-client protection</div>
            </div>
            <button onClick={() => { setUsePkce(!usePkce); reset(); }}
              className={cn("relative h-6 w-11 rounded-full transition-colors", usePkce ? "bg-emerald-500" : "bg-slate-700")}>
              <span className={cn("absolute top-0.5 h-5 w-5 rounded-full bg-white shadow transition-all", usePkce ? "left-[22px]" : "left-0.5")} />
            </button>
          </div>
          <div className="grid grid-cols-2 gap-2">
            <div className="rounded-xl border border-white/[0.07] bg-[#070b18] px-3 py-2">
              <div className="text-[10px] font-bold uppercase tracking-widest text-slate-500">Flow</div>
              <div className="mt-0.5 font-mono text-[11.5px] font-bold text-indigo-300">code + PKCE</div>
            </div>
            <div className="rounded-xl border border-white/[0.07] bg-[#070b18] px-3 py-2">
              <div className="text-[10px] font-bold uppercase tracking-widest text-slate-500">Issuer</div>
              <div className="mt-0.5 truncate font-mono text-[11.5px] font-bold text-slate-300" title={issuer}>{issuer.replace("https://", "")}</div>
            </div>
          </div>
          {/* controls */}
          <div className="flex gap-2 pt-1">
            <button onClick={() => { if (phase === "idle" || phase === "denied") { reset(); setTimeout(() => { setAutoPlaying(true); }, 50); } else setAutoPlaying(!autoPlaying); }}
              className="glow-indigo flex flex-1 items-center justify-center gap-1.5 rounded-xl bg-gradient-to-r from-indigo-600 to-violet-600 px-3 py-2.5 text-[13px] font-bold text-white hover:brightness-110">
              <Play size={15} /> {autoPlaying ? "Pause" : phase === "idle" ? "Run Full Flow" : "Auto-play"}
            </button>
            <button onClick={next} disabled={phase === "done" || autoPlaying}
              className="flex items-center gap-1 rounded-xl border border-white/10 bg-white/[0.05] px-3 py-2.5 text-[13px] font-bold text-white hover:border-indigo-500/40 disabled:opacity-40">
              <StepForward size={15} /> Step
            </button>
            <button onClick={reset} className="flex items-center rounded-xl border border-white/10 bg-white/[0.05] px-3 py-2.5 text-slate-300 hover:border-rose-500/40 hover:text-rose-300">
              <RotateCcw size={15} />
            </button>
          </div>
        </div>
      </div>

      {/* Flow visualization */}
      <div className="space-y-4">
        {/* Step cards */}
        <div className="grid gap-3 sm:grid-cols-2 2xl:grid-cols-4">
          {STEPS.map((s) => {
            const idx = s.n - 1;
            const done = phaseIndex > idx || phase === "done";
            const active = phaseIndex === idx && phase !== "done";
            const Icon = s.icon;
            return (
              <div key={s.id} className={cn("card card-hover relative overflow-hidden p-3.5",
                active && "border-indigo-500/50 glow-indigo",
                done && "border-emerald-500/30")}>
                {active && <div className="absolute inset-x-0 top-0 h-[2px] bg-gradient-to-r from-indigo-500 to-cyan-400" />}
                <div className="flex items-center gap-2.5">
                  <div className={cn("flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border",
                    done ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-300"
                    : active ? "border-indigo-500/50 bg-indigo-500/20 text-indigo-200"
                    : "border-white/10 bg-white/[0.04] text-slate-500")}>
                    {done ? <Check size={17} /> : <Icon size={17} />}
                  </div>
                  <div className="min-w-0">
                    <div className="font-mono text-[10px] font-bold uppercase tracking-widest text-slate-500">Step {s.n}</div>
                    <div className="truncate text-[13px] font-bold text-white">{s.title}</div>
                  </div>
                </div>
                <p className="mt-2 text-[11.5px] leading-relaxed text-slate-400">{s.desc}</p>
                <div className="mt-2.5">
                  {done ? <span className="inline-flex items-center gap-1 rounded-md bg-emerald-500/10 px-2 py-0.5 font-mono text-[10.5px] font-bold text-emerald-300"><Check size={11} /> complete</span>
                  : active ? <span className="inline-flex items-center gap-1 rounded-md bg-indigo-500/15 px-2 py-0.5 font-mono text-[10.5px] font-bold text-indigo-300"><span className="h-1.5 w-1.5 animate-pulse rounded-full bg-indigo-400" /> running</span>
                  : <span className="inline-flex items-center gap-1 rounded-md bg-white/[0.05] px-2 py-0.5 font-mono text-[10.5px] text-slate-500">pending</span>}
                </div>
              </div>
            );
          })}
        </div>

        {/* Detail panel per phase */}
        <div className="card overflow-hidden">
          <div className="flex items-center gap-2 border-b border-white/[0.06] px-4 py-3">
            <Fingerprint size={15} className="text-indigo-400" />
            <h3 className="text-[13.5px] font-bold text-white">
              {phase === "idle" && "Ready to simulate — press Run or Step"}
              {phase === "redirect" && "Step 1 · Authorization Redirect"}
              {phase === "consent" && "Step 2 · Consent Grant"}
              {phase === "exchange" && "Step 3 · Code Exchange"}
              {phase === "resource" && "Step 4 · Protected Resource"}
              {phase === "done" && "Flow Complete · Session Established"}
              {phase === "denied" && "Flow Aborted · Access Denied"}
            </h3>
            <div className="flex-1" />
            {phase !== "idle" && phase !== "denied" && (
              <button onClick={next} disabled={phase === "done" || autoPlaying}
                className="flex items-center gap-1 rounded-lg bg-indigo-600 px-2.5 py-1.5 text-[12px] font-bold text-white hover:bg-indigo-500 disabled:opacity-40">
                {phase === "consent" ? "Approve & Continue" : phase === "done" ? "Done" : "Next Step"} <ChevronRight size={14} />
              </button>
            )}
          </div>

          <div className="p-4">
            {phase === "idle" && (
              <div className="rounded-xl border border-dashed border-white/10 bg-[#070b18] p-6 text-center">
                <Globe size={26} className="mx-auto text-slate-600" />
                <p className="mx-auto mt-2 max-w-md text-[13px] leading-relaxed text-slate-400">
                  The simulator will walk through a real <span className="font-mono text-indigo-300">authorization_code</span> grant
                  against <span className="font-mono text-slate-300">{issuer}</span> — building the authorize URL,
                  collecting consent, exchanging the code with PKCE, and calling a protected API.
                </p>
                <PreviewUrl url={authUrl} onCopy={() => copy(authUrl, "authurl")} copied={copied === "authurl"} />
              </div>
            )}

            {phase === "redirect" && (
              <div className="space-y-3 animate-slide-up">
                <div className="flex items-center gap-2 text-[12px] text-slate-400">
                  <span className="rounded-md bg-indigo-500/15 px-2 py-0.5 font-mono text-[11px] font-bold text-indigo-300">CLIENT APP</span>
                  <span className="flex-1 border-t border-dashed border-indigo-500/30" />
                  <span className="font-mono text-[11px]">302 redirect</span>
                  <span className="flex-1 border-t border-dashed border-indigo-500/30" />
                  <span className="rounded-md bg-violet-500/15 px-2 py-0.5 font-mono text-[11px] font-bold text-violet-300">AUTH SERVER</span>
                </div>
                <PreviewUrl url={authUrl} onCopy={() => copy(authUrl, "authurl")} copied={copied === "authurl"} />
                <div className="grid gap-2 sm:grid-cols-3">
                  <ParamBox k="state" v={flow.state} mono />
                  <ParamBox k={usePkce ? "code_challenge (S256)" : "PKCE"} v={usePkce ? flow.challenge : "disabled"} mono warn={!usePkce} />
                  <ParamBox k="scope" v={scopes.join(" ")} />
                </div>
              </div>
            )}

            {phase === "consent" && (
              <div className="mx-auto max-w-md animate-slide-up overflow-hidden rounded-2xl border border-white/10 bg-[#0a0f1e] shadow-2xl">
                <div className="border-b border-white/[0.07] bg-gradient-to-r from-indigo-600/20 to-violet-600/10 px-5 py-4">
                  <div className="flex items-center gap-2.5">
                    <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-gradient-to-br from-indigo-600 to-violet-700 font-bold text-white">A</div>
                    <div>
                      <div className="text-[13.5px] font-bold text-white">Authorize AuthPulse Demo?</div>
                      <div className="font-mono text-[11px] text-slate-400">{clientId}</div>
                    </div>
                  </div>
                </div>
                <div className="space-y-2 px-5 py-4">
                  <div className="text-[11px] font-bold uppercase tracking-widest text-slate-500">This app wants to</div>
                  {scopes.map((s) => (
                    <div key={s} className="flex items-center gap-2.5 rounded-lg border border-white/[0.07] bg-white/[0.02] px-3 py-2">
                      <ShieldCheck size={14} className="shrink-0 text-emerald-400" />
                      <span className="font-mono text-[12px] text-slate-200">{s}</span>
                      <span className="ml-auto text-[11px] text-slate-500">{SCOPES.find((x) => x.id === s)?.desc}</span>
                    </div>
                  ))}
                  <div className="flex gap-2 pt-2">
                    <button onClick={deny} className="flex flex-1 items-center justify-center gap-1.5 rounded-xl border border-rose-500/30 bg-rose-500/10 px-3 py-2.5 text-[13px] font-bold text-rose-300 hover:bg-rose-500/20">
                      <Ban size={14} /> Deny
                    </button>
                    <button onClick={() => stepTo("exchange")} className="glow-indigo flex flex-[2] items-center justify-center gap-1.5 rounded-xl bg-gradient-to-r from-indigo-600 to-violet-600 px-3 py-2.5 text-[13px] font-bold text-white hover:brightness-110">
                      <Check size={15} /> Approve access
                    </button>
                  </div>
                </div>
              </div>
            )}

            {phase === "exchange" && (
              <div className="grid gap-3 animate-slide-up lg:grid-cols-2">
                <div className="rounded-xl border border-white/[0.07] bg-[#070b18] p-3.5">
                  <div className="mb-2 flex items-center justify-between">
                    <span className="font-mono text-[11px] font-bold text-indigo-300">POST /token · request</span>
                    <span className="rounded bg-amber-500/10 px-1.5 py-0.5 font-mono text-[10px] text-amber-300">x-www-form-urlencoded</span>
                  </div>
                  <pre className="overflow-x-auto font-mono text-[11.5px] leading-relaxed text-slate-300">
{`grant_type=authorization_code
code=${flow.code.slice(0, 28)}…
redirect_uri=${redirectUri}
client_id=${clientId}
code_verifier=${usePkce ? flow.verifier.slice(0, 28) + "…" : "(none — PKCE off!)"}`}
                  </pre>
                </div>
                <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/[0.04] p-3.5">
                  <div className="mb-2 flex items-center justify-between">
                    <span className="font-mono text-[11px] font-bold text-emerald-300">200 OK · token set</span>
                    <button onClick={() => onUseToken(flow.accessToken)} className="flex items-center gap-1 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-2 py-1 text-[11px] font-bold text-emerald-300 hover:bg-emerald-500/20">
                      <ExternalLink size={11} /> Inspect in decoder
                    </button>
                  </div>
                  <div className="space-y-1.5 font-mono text-[11px]">
                    <TokenLine label="access_token" value={flow.accessToken} id="oa-at" copied={copied} onCopy={copy} accent="#c4b5fd" />
                    <TokenLine label="id_token" value={flow.idToken} id="oa-id" copied={copied} onCopy={copy} accent="#6ee7b7" />
                    <div className="flex items-center gap-2 text-slate-400">
                      <span className="w-24 shrink-0 text-slate-500">refresh_token</span>
                      <span className="truncate text-slate-300">{flow.refreshToken.slice(0, 30)}…</span>
                    </div>
                    <div className="flex items-center gap-2 text-slate-400">
                      <span className="w-24 shrink-0 text-slate-500">expires_in</span>
                      <span className="text-amber-300">3600</span>
                      <span className="text-slate-600">·</span>
                      <span className="text-slate-500">token_type</span>
                      <span className="text-slate-200">Bearer</span>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {(phase === "resource" || phase === "done") && (
              <div className="grid gap-3 animate-slide-up lg:grid-cols-2">
                <div className="rounded-xl border border-white/[0.07] bg-[#070b18] p-3.5">
                  <div className="mb-2 font-mono text-[11px] font-bold text-indigo-300">GET /v1/me · request</div>
                  <pre className="overflow-x-auto font-mono text-[11.5px] leading-relaxed text-slate-300">
{`GET https://api.authpulse.dev/v1/me
Authorization: Bearer ${flow.accessToken.slice(0, 26)}…
Accept: application/json`}
                  </pre>
                  <div className="mt-3 flex items-center gap-2 rounded-lg border border-white/[0.07] bg-white/[0.02] px-2.5 py-2">
                    {usePkce ? <Lock size={13} className="text-emerald-400" /> : <Unlock size={13} className="text-amber-400" />}
                    <span className="text-[11.5px] text-slate-400">
                      {usePkce ? "Bearer token bound to PKCE-secured grant" : "Warning: issued without PKCE — vulnerable to code interception"}
                    </span>
                  </div>
                </div>
                <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/[0.04] p-3.5">
                  <div className="mb-2 font-mono text-[11px] font-bold text-emerald-300">200 OK · application/json · 42ms</div>
                  <pre className="overflow-x-auto font-mono text-[11.5px] leading-relaxed">
                    <code>
                      <span className="text-slate-500">{"{"}</span>{"\n"}
                      {"  "}<span className="claim-key">"id"</span><span className="text-slate-500">:</span> <span className="claim-string">"usr_9f3a2b1c"</span><span className="text-slate-500">,</span>{"\n"}
                      {"  "}<span className="claim-key">"name"</span><span className="text-slate-500">:</span> <span className="claim-string">"Maya Chen"</span><span className="text-slate-500">,</span>{"\n"}
                      {"  "}<span className="claim-key">"email"</span><span className="text-slate-500">:</span> <span className="claim-string">"maya.chen@authpulse.dev"</span><span className="text-slate-500">,</span>{"\n"}
                      {"  "}<span className="claim-key">"plan"</span><span className="text-slate-500">:</span> <span className="claim-string">"pro"</span><span className="text-slate-500">,</span>{"\n"}
                      {"  "}<span className="claim-key">"mfa"</span><span className="text-slate-500">:</span> <span className="claim-bool">true</span>{"\n"}
                      <span className="text-slate-500">{"}"}</span>
                    </code>
                  </pre>
                </div>
              </div>
            )}

            {phase === "denied" && (
              <div className="rounded-xl border border-rose-500/25 bg-rose-500/[0.06] p-6 text-center animate-slide-up">
                <Ban size={26} className="mx-auto text-rose-400" />
                <p className="mt-2 font-mono text-[12.5px] text-rose-200">error=access_denied&error_description=User+denied+consent</p>
                <p className="mt-1 text-[12.5px] text-slate-400">The client received an error redirect. Reset and run again to approve.</p>
                <button onClick={reset} className="mt-3 rounded-xl border border-white/10 bg-white/[0.05] px-4 py-2 text-[13px] font-bold text-white hover:border-indigo-500/40">
                  Reset simulation
                </button>
              </div>
            )}
          </div>
        </div>

        {/* Live HTTP log */}
        <div className="card overflow-hidden">
          <div className="flex items-center gap-2 border-b border-white/[0.06] px-4 py-2.5">
            <Terminal size={14} className="text-emerald-400" />
            <h3 className="font-mono text-[12px] font-bold text-slate-200">live HTTP trace</h3>
            <span className="flex items-center gap-1 font-mono text-[10.5px] text-slate-500">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-live text-emerald-400" /> {logs.length} events
            </span>
            <div className="flex-1" />
            <button onClick={() => setLogs([])} className="font-mono text-[11px] text-slate-500 hover:text-white">clear</button>
          </div>
          <div ref={logRef} className="h-40 overflow-y-auto bg-[#05070f] p-3 font-mono text-[11.5px] leading-relaxed">
            {logs.length === 0 ? (
              <div className="flex h-full items-center justify-center text-slate-600">
                <span className="mr-2 text-emerald-500">❯</span> awaiting flow start — every redirect, POST and response will be traced here
              </div>
            ) : (
              logs.map((l, i) => (
                <div key={i} className="flex gap-2.5 py-0.5 animate-slide-up">
                  <span className="shrink-0 text-slate-600">{l.t}</span>
                  <span className={cn("shrink-0 font-bold",
                    l.tone === "ok" ? "text-emerald-400" : l.tone === "warn" ? "text-amber-400"
                    : l.tone === "req" ? "text-indigo-300" : l.tone === "res" ? "text-violet-300" : "text-slate-400")}>
                    [{l.actor}]
                  </span>
                  <span className="break-all text-slate-300">{l.msg}</span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function PreviewUrl({ url, onCopy, copied }: { url: string; onCopy: () => void; copied: boolean }) {
  return (
    <div className="mt-4 rounded-xl border border-white/[0.07] bg-[#070b18] p-3 text-left">
      <div className="mb-1.5 flex items-center justify-between">
        <span className="font-mono text-[10.5px] font-bold uppercase tracking-widest text-slate-500">Authorization URL preview</span>
        <button onClick={onCopy} className="flex items-center gap-1 font-mono text-[11px] text-slate-400 hover:text-white">
          {copied ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />} {copied ? "copied" : "copy"}
        </button>
      </div>
      <div className="break-all font-mono text-[11.5px] leading-relaxed text-indigo-200/90">{url}</div>
    </div>
  );
}

function ParamBox({ k, v, mono = false, warn = false }: { k: string; v: string; mono?: boolean; warn?: boolean }) {
  return (
    <div className={cn("rounded-xl border bg-[#070b18] px-3 py-2", warn ? "border-amber-500/30" : "border-white/[0.07]")}>
      <div className="text-[10px] font-bold uppercase tracking-widest text-slate-500">{k}</div>
      <div className={cn("mt-0.5 truncate text-[12px]", mono ? "font-mono text-indigo-200" : "text-slate-200", warn && "text-amber-300")} title={v}>{v}</div>
    </div>
  );
}

function TokenLine({ label, value, id, copied, onCopy, accent }: { label: string; value: string; id: string; copied: string | null; onCopy: (t: string, id: string) => void; accent: string }) {
  return (
    <div className="flex items-center gap-2">
      <span className="w-24 shrink-0 text-slate-500">{label}</span>
      <span className="truncate" style={{ color: accent }}>{value.slice(0, 34)}…</span>
      <button onClick={() => onCopy(value, id)} className="ml-auto shrink-0 text-slate-500 hover:text-white">
        {copied === id ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
      </button>
    </div>
  );
}
