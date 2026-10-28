import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ScanSearch,
  ArrowLeftRight,
  Database,
  ShieldCheck,
  Loader2,
  CheckCircle2,
  FileJson,
  Timer,
  KeyRound,
  LayoutDashboard,
} from "lucide-react";
import Header from "./components/Header";
import JwtDecoder from "./components/JwtDecoder";
import OAuthSimulator from "./components/OAuthSimulator";
import SessionManager, { type SessionEntry } from "./components/SessionManager";
import SecurityChecker from "./components/SecurityChecker";
import { buildMockTokens, ENVIRONMENTS, type EnvId, type TokenFixture } from "./data/mockTokens";
import { getTokenStatus, parseJwt, byteSize } from "./utils/jwt";
import { cn } from "./utils/cn";

type Tab = "inspector" | "oauth" | "sessions" | "security";

const TABS: { id: Tab; label: string; desc: string; icon: any }[] = [
  { id: "inspector", label: "JWT Inspector", desc: "Decode & verify", icon: ScanSearch },
  { id: "oauth", label: "OAuth Simulator", desc: "Code + PKCE flow", icon: ArrowLeftRight },
  { id: "sessions", label: "Sessions", desc: "Storage & cookies", icon: Database },
  { id: "security", label: "Health Check", desc: "Audit & score", icon: ShieldCheck },
];

export default function App() {
  const [env, setEnv] = useState<EnvId>("development");
  const [fixtures, setFixtures] = useState<TokenFixture[]>([]);
  const [loading, setLoading] = useState(true);
  const [rawToken, setRawToken] = useState("");
  const [activeFixtureId, setActiveFixtureId] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<Tab>("inspector");
  const [entries, setEntries] = useState<SessionEntry[]>([]);
  const [toast, setToast] = useState<string | null>(null);

  const issuer = ENVIRONMENTS.find((e) => e.id === env)!.issuer;

  // Build fixtures (async HMAC signing) + seed storage
  useEffect(() => {
    let cancelled = false;
    (async () => {
      const f = await buildMockTokens();
      if (cancelled) return;
      setFixtures(f);
      setRawToken(f[0].token);
      setActiveFixtureId(f[0].id);
      // seed localStorage demo entry once
      try {
        if (!localStorage.getItem(f[0].storageKey)) {
          localStorage.setItem(f[0].storageKey, f[0].token);
        }
        const seeded: SessionEntry[] = [
          {
            id: "seed-ls",
            key: f[0].storageKey,
            token: localStorage.getItem(f[0].storageKey) ?? f[0].token,
            origin: "localStorage",
            secure: location.protocol === "https:",
            httpOnly: false,
            sameSite: "Lax",
            createdAt: Date.now() - 15 * 60 * 1000,
          },
          {
            id: "seed-mem",
            key: "memory:oauth-access-token",
            token: f[1].token,
            origin: "memory",
            secure: true,
            httpOnly: false,
            sameSite: "Strict",
            createdAt: Date.now() - 5 * 60 * 1000,
          },
        ];
        setEntries(seeded);
      } catch {
        setEntries([
          { id: "seed-mem", key: "memory:oauth-access-token", token: f[1].token, origin: "memory", secure: true, httpOnly: false, sameSite: "Strict", createdAt: Date.now() },
        ]);
      }
      setLoading(false);
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const showToast = useCallback((msg: string) => {
    setToast(msg);
    setTimeout(() => setToast(null), 2400);
  }, []);

  const decoded = useMemo(() => parseJwt(rawToken), [rawToken]);
  const status = useMemo(() => getTokenStatus(decoded.payload), [decoded]);

  const handleClear = () => {
    setRawToken("");
    setActiveFixtureId(null);
    showToast("Token buffer cleared");
  };

  const handleImportSample = () => {
    if (fixtures.length === 0) return;
    const idx = fixtures.findIndex((f) => f.id === activeFixtureId);
    const next = fixtures[(idx + 1) % fixtures.length];
    setRawToken(next.token);
    setActiveFixtureId(next.id);
    setActiveTab("inspector");
    showToast(`Imported: ${next.name}`);
  };

  const handleSaveToSession = () => {
    if (!decoded.isValidStructure) return;
    const key = `authpulse:session:${Date.now().toString(36)}`;
    try {
      localStorage.setItem(key, decoded.raw);
    } catch {}
    setEntries((prev) => [
      ...prev,
      { id: `${Date.now()}`, key, token: decoded.raw, origin: "localStorage", secure: location.protocol === "https:", httpOnly: false, sameSite: "Lax", createdAt: Date.now() },
    ]);
    showToast("Token persisted to localStorage");
  };

  const handleLoadFromSession = (token: string) => {
    setRawToken(token);
    setActiveFixtureId(null);
    setActiveTab("inspector");
    showToast("Loaded into inspector");
  };

  const handleOAuthToken = (token: string) => {
    setRawToken(token);
    setActiveFixtureId(null);
    setActiveTab("inspector");
    showToast("OAuth access token loaded into inspector");
  };

  if (loading) {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center gap-4 bg-[#060913]">
        <div className="relative">
          <div className="absolute inset-0 rounded-2xl bg-indigo-500/50 blur-2xl" />
          <div className="relative flex h-16 w-16 items-center justify-center rounded-2xl border border-indigo-400/40 bg-gradient-to-br from-indigo-600 to-violet-700">
            <Loader2 className="h-7 w-7 animate-spin text-white" />
          </div>
        </div>
        <div className="text-center">
          <div className="text-[16px] font-bold text-white">Initializing AuthPulse</div>
          <div className="mt-1 font-mono text-[12px] text-slate-500">signing fixtures · HMAC-SHA256 · seeding sessions…</div>
        </div>
      </div>
    );
  }

  return (
    <div className="relative min-h-screen bg-[#060913]">
      {/* backdrop */}
      <div className="pointer-events-none fixed inset-0 bg-grid opacity-60" />
      <div className="pointer-events-none fixed -left-40 -top-40 h-[480px] w-[480px] rounded-full bg-indigo-600/12 blur-[120px]" />
      <div className="pointer-events-none fixed -right-40 top-1/3 h-[420px] w-[420px] rounded-full bg-emerald-500/[0.07] blur-[120px]" />
      <div className="pointer-events-none fixed bottom-0 left-1/3 h-[300px] w-[500px] rounded-full bg-violet-600/[0.08] blur-[120px]" />

      <div className="relative">
        <Header
          env={env}
          setEnv={setEnv}
          onClear={handleClear}
          onImportSample={handleImportSample}
          tokenCount={(rawToken.trim() ? 1 : 0) + entries.length}
          hasToken={!!rawToken.trim()}
        />

        <main className="mx-auto max-w-[1440px] px-4 pb-16 pt-5 sm:px-6">
          {/* Workspace hero strip */}
          <div className="mb-4 flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
            <div>
              <div className="flex items-center gap-2 font-mono text-[11px] font-bold uppercase tracking-widest text-indigo-300">
                <LayoutDashboard size={13} />
                Developer workspace · {ENVIRONMENTS.find((e) => e.id === env)!.label}
              </div>
              <h2 className="mt-1 text-[22px] font-extrabold tracking-tight text-white sm:text-[26px]">
                Token command center
              </h2>
              <p className="mt-0.5 max-w-xl text-[13px] text-slate-400">
                Decode JWTs, simulate the full OAuth code grant, audit storage flags and score token health — all locally in your browser. Nothing leaves this page.
              </p>
            </div>
            {/* live token meta chips */}
            <div className="flex flex-wrap gap-2">
              <MetaChip icon={FileJson} label="alg" value={decoded.header?.alg ?? "—"} tone={decoded.header?.alg === "none" ? "rose" : "indigo"} />
              <MetaChip icon={KeyRound} label="size" value={rawToken.trim() ? `${byteSize(decoded.raw)} B` : "—"} tone="slate" />
              <MetaChip
                icon={Timer}
                label="exp"
                value={!decoded.payload ? "—" : status.state === "expired" ? "expired" : status.state === "no-exp" ? "never" : status.state === "expiring" ? "expiring" : "valid"}
                tone={status.state === "expired" ? "rose" : status.state === "expiring" ? "amber" : status.state === "valid" ? "emerald" : "slate"}
              />
              <MetaChip icon={Database} label="sessions" value={`${entries.length}`} tone="emerald" />
            </div>
          </div>

          {/* Tab bar */}
          <div className="sticky top-[66px] z-40 -mx-4 mb-4 border-y border-white/[0.06] bg-[#060913]/85 px-4 py-2 backdrop-blur-xl sm:-mx-6 sm:px-6">
            <div className="mx-auto flex max-w-[1440px] gap-2 overflow-x-auto">
              {TABS.map((t) => {
                const Icon = t.icon;
                const active = activeTab === t.id;
                return (
                  <button
                    key={t.id}
                    onClick={() => setActiveTab(t.id)}
                    className={cn(
                      "flex min-w-fit flex-1 items-center gap-2.5 rounded-xl border px-3.5 py-2.5 text-left transition-all sm:flex-none sm:pr-6",
                      active
                        ? "border-indigo-500/50 bg-indigo-500/[0.13] shadow-lg shadow-indigo-950/40"
                        : "border-transparent hover:border-white/10 hover:bg-white/[0.04]"
                    )}
                  >
                    <span className={cn(
                      "flex h-8 w-8 items-center justify-center rounded-lg",
                      active ? "bg-gradient-to-br from-indigo-500 to-violet-600 text-white" : "bg-white/[0.05] text-slate-400"
                    )}>
                      <Icon size={16} />
                    </span>
                    <span>
                      <span className={cn("block text-[13.5px] font-bold leading-none", active ? "text-white" : "text-slate-300")}>{t.label}</span>
                      <span className="mt-1 block font-mono text-[10.5px] leading-none text-slate-500">{t.desc}</span>
                    </span>
                    {t.id === "sessions" && entries.length > 0 && (
                      <span className="ml-1 rounded-full bg-emerald-500/15 px-1.5 py-0.5 font-mono text-[10px] font-bold text-emerald-300">
                        {entries.length}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Views */}
          <div key={activeTab} className="animate-slide-up">
            {activeTab === "inspector" && (
              <JwtDecoder
                rawToken={rawToken}
                setRawToken={setRawToken}
                fixtures={fixtures}
                activeFixtureId={activeFixtureId}
                setActiveFixtureId={setActiveFixtureId}
                onSaveToSession={handleSaveToSession}
              />
            )}
            {activeTab === "oauth" && <OAuthSimulator issuer={issuer} onUseToken={handleOAuthToken} />}
            {activeTab === "sessions" && (
              <SessionManager entries={entries} setEntries={setEntries} currentToken={rawToken} onLoad={handleLoadFromSession} />
            )}
            {activeTab === "security" && <SecurityChecker token={rawToken} issuer={issuer} />}
          </div>

          {/* Footer */}
          <footer className="mt-10 border-t border-white/[0.06] pt-6">
            <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
              <div className="flex items-center gap-2.5">
                <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-indigo-400/40 bg-gradient-to-br from-indigo-600 to-violet-700">
                  <ShieldCheck size={16} className="text-white" />
                </div>
                <div>
                  <div className="text-[13px] font-bold text-white">AuthPulse · Security Developer Workspace</div>
                  <div className="font-mono text-[11px] text-slate-500">100% client-side · RFC 7519 JWT · RFC 6749 OAuth 2.0 · OIDC Core</div>
                </div>
              </div>
              <div className="flex flex-wrap gap-x-5 gap-y-1 font-mono text-[11.5px] text-slate-500">
                <span><span className="text-indigo-400">◆</span> HS256 HMAC verified in-browser</span>
                <span><span className="text-emerald-400">◆</span> PKCE S256 enforced</span>
                <span><span className="text-amber-400">◆</span> zero token exfiltration</span>
              </div>
            </div>
          </footer>
        </main>

        {/* Toast */}
        {toast && (
          <div className="fixed bottom-6 left-1/2 z-[100] -translate-x-1/2 animate-slide-up">
            <div className="glow-emerald flex items-center gap-2 rounded-xl border border-emerald-500/40 bg-[#0b1526]/95 px-4 py-2.5 text-[13px] font-semibold text-emerald-200 shadow-2xl backdrop-blur-xl">
              <CheckCircle2 size={16} className="text-emerald-400" />
              {toast}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function MetaChip({ icon: Icon, label, value, tone }: { icon: any; label: string; value: string; tone: "indigo" | "emerald" | "amber" | "rose" | "slate" }) {
  const tones: Record<string, string> = {
    indigo: "border-indigo-500/30 bg-indigo-500/10 text-indigo-200",
    emerald: "border-emerald-500/30 bg-emerald-500/10 text-emerald-200",
    amber: "border-amber-500/30 bg-amber-500/10 text-amber-200",
    rose: "border-rose-500/30 bg-rose-500/10 text-rose-200",
    slate: "border-white/10 bg-white/[0.04] text-slate-300",
  };
  return (
    <div className={cn("flex items-center gap-2 rounded-xl border px-3 py-1.5", tones[tone])}>
      <Icon size={14} className="opacity-70" />
      <span className="font-mono text-[10.5px] uppercase tracking-wider opacity-70">{label}</span>
      <span className="font-mono text-[12.5px] font-bold">{value}</span>
    </div>
  );
}
