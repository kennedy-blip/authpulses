import { useEffect, useState } from "react";
import {
  ShieldCheck,
  ChevronDown,
  Trash2,
  Sparkles,
  Activity,
  Check,
  Menu,
  X,
} from "lucide-react";
import { ENVIRONMENTS, type EnvId } from "../data/mockTokens";
import { cn } from "../utils/cn";

interface Props {
  env: EnvId;
  setEnv: (e: EnvId) => void;
  onClear: () => void;
  onImportSample: () => void;
  tokenCount: number;
  hasToken: boolean;
}

export default function Header({ env, setEnv, onClear, onImportSample, tokenCount, hasToken }: Props) {
  const [envOpen, setEnvOpen] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [clock, setClock] = useState(new Date());

  useEffect(() => {
    const t = setInterval(() => setClock(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  const activeEnv = ENVIRONMENTS.find((e) => e.id === env)!;

  return (
    <header className="sticky top-0 z-50 border-b border-indigo-500/15 bg-[#060913]/85 backdrop-blur-xl">
      {/* top glow line */}
      <div className="h-[2px] w-full bg-gradient-to-r from-transparent via-indigo-500/70 to-transparent" />
      <div className="mx-auto flex max-w-[1440px] items-center gap-3 px-4 py-3 sm:px-6">
        {/* Logo */}
        <div className="flex items-center gap-3">
          <div className="relative">
            <div className="absolute inset-0 rounded-xl bg-indigo-500/50 blur-lg" />
            <div className="relative flex h-10 w-10 items-center justify-center rounded-xl border border-indigo-400/40 bg-gradient-to-br from-indigo-600 via-indigo-600 to-violet-700 shadow-lg shadow-indigo-900/50">
              <ShieldCheck className="h-5.5 w-5.5 text-white" size={22} strokeWidth={2.2} />
            </div>
            <span className="absolute -right-0.5 -top-0.5 h-2.5 w-2.5 rounded-full bg-emerald-400 animate-live text-emerald-400" />
          </div>
          <div className="leading-tight">
            <div className="flex items-center gap-2">
              <h1 className="text-[17px] font-extrabold tracking-tight text-white">
                Auth<span className="bg-gradient-to-r from-indigo-400 to-cyan-300 bg-clip-text text-transparent">Pulse</span>
              </h1>
              <span className="hidden rounded-md border border-emerald-400/30 bg-emerald-400/10 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-emerald-300 sm:inline-block">
                v2.4.1
              </span>
            </div>
            <p className="hidden text-[11.5px] text-slate-400 sm:block">
              JWT Decoder · OAuth Simulator · Session Inspector
            </p>
          </div>
        </div>

        <div className="flex-1" />

        {/* Live clock (desktop) */}
        <div className="hidden items-center gap-2 rounded-lg border border-white/10 bg-white/[0.03] px-3 py-1.5 font-mono text-[11.5px] text-slate-300 lg:flex">
          <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-live text-emerald-400" />
          {clock.toLocaleTimeString("en-US", { hour12: false })} UTC{clock.getTimezoneOffset() <= 0 ? "+" : ""}
          <span className="text-slate-500">·</span>
          <Activity size={13} className="text-indigo-400" />
          <span className="text-slate-400">buffer: {tokenCount}</span>
        </div>

        {/* Environment selector */}
        <div className="relative hidden md:block">
          <button
            onClick={() => setEnvOpen(!envOpen)}
            className="flex items-center gap-2.5 rounded-xl border border-white/10 bg-white/[0.04] px-3 py-2 text-[13px] font-medium text-slate-200 transition-all hover:border-indigo-500/40 hover:bg-white/[0.06]"
          >
            <span className="h-2 w-2 rounded-full" style={{ background: activeEnv.color, boxShadow: `0 0 8px ${activeEnv.color}` }} />
            <span className="text-slate-400">Env:</span>
            <span className="font-semibold text-white">{activeEnv.label}</span>
            <ChevronDown size={15} className={cn("text-slate-400 transition-transform", envOpen && "rotate-180")} />
          </button>
          {envOpen && (
            <>
              <div className="fixed inset-0 z-10" onClick={() => setEnvOpen(false)} />
              <div className="absolute right-0 z-20 mt-2 w-72 overflow-hidden rounded-xl border border-indigo-500/20 bg-[#10172a] p-1.5 shadow-2xl shadow-black/60 animate-slide-up">
                <div className="px-2.5 pb-1.5 pt-2 text-[10.5px] font-bold uppercase tracking-widest text-slate-500">
                  Issuer environment
                </div>
                {ENVIRONMENTS.map((e) => (
                  <button
                    key={e.id}
                    onClick={() => {
                      setEnv(e.id);
                      setEnvOpen(false);
                    }}
                    className={cn(
                      "flex w-full items-center gap-3 rounded-lg px-2.5 py-2.5 text-left transition-colors",
                      e.id === env ? "bg-indigo-500/15" : "hover:bg-white/[0.04]"
                    )}
                  >
                    <span className="h-2.5 w-2.5 shrink-0 rounded-full" style={{ background: e.color, boxShadow: `0 0 8px ${e.color}` }} />
                    <span className="min-w-0 flex-1">
                      <span className="block text-[13px] font-semibold text-white">{e.label}</span>
                      <span className="block truncate font-mono text-[11px] text-slate-400">{e.issuer}</span>
                    </span>
                    {e.id === env && <Check size={15} className="shrink-0 text-emerald-400" />}
                  </button>
                ))}
              </div>
            </>
          )}
        </div>

        {/* Quick actions (desktop) */}
        <div className="hidden items-center gap-2 md:flex">
          <button
            onClick={onClear}
            disabled={!hasToken}
            className="flex items-center gap-1.5 rounded-xl border border-rose-500/25 bg-rose-500/10 px-3 py-2 text-[13px] font-semibold text-rose-300 transition-all hover:border-rose-500/50 hover:bg-rose-500/20 disabled:cursor-not-allowed disabled:opacity-40"
          >
            <Trash2 size={15} />
            Clear Buffer
          </button>
          <button
            onClick={onImportSample}
            className="glow-indigo flex items-center gap-1.5 rounded-xl border border-indigo-400/40 bg-gradient-to-r from-indigo-600 to-violet-600 px-3.5 py-2 text-[13px] font-semibold text-white transition-all hover:brightness-110 active:scale-[0.98]"
          >
            <Sparkles size={15} />
            Import Sample Token
          </button>
        </div>

        {/* Mobile menu toggle */}
        <button
          onClick={() => setMobileOpen(!mobileOpen)}
          className="rounded-xl border border-white/10 bg-white/[0.04] p-2 text-slate-300 md:hidden"
        >
          {mobileOpen ? <X size={18} /> : <Menu size={18} />}
        </button>
      </div>

      {/* Mobile dropdown */}
      {mobileOpen && (
        <div className="border-t border-white/10 bg-[#0a0f1e] px-4 py-3 md:hidden animate-slide-up">
          <div className="mb-1 text-[10.5px] font-bold uppercase tracking-widest text-slate-500">Environment</div>
          <div className="mb-3 grid grid-cols-3 gap-2">
            {ENVIRONMENTS.map((e) => (
              <button
                key={e.id}
                onClick={() => setEnv(e.id)}
                className={cn(
                  "flex items-center justify-center gap-1.5 rounded-lg border px-2 py-2 text-[12px] font-semibold",
                  e.id === env
                    ? "border-indigo-500/50 bg-indigo-500/15 text-white"
                    : "border-white/10 bg-white/[0.03] text-slate-400"
                )}
              >
                <span className="h-1.5 w-1.5 rounded-full" style={{ background: e.color }} />
                {e.label.split(" ")[0]}
              </button>
            ))}
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => {
                onClear();
                setMobileOpen(false);
              }}
              className="flex flex-1 items-center justify-center gap-1.5 rounded-xl border border-rose-500/25 bg-rose-500/10 px-3 py-2.5 text-[13px] font-semibold text-rose-300"
            >
              <Trash2 size={15} /> Clear Buffer
            </button>
            <button
              onClick={() => {
                onImportSample();
                setMobileOpen(false);
              }}
              className="flex flex-1 items-center justify-center gap-1.5 rounded-xl bg-gradient-to-r from-indigo-600 to-violet-600 px-3 py-2.5 text-[13px] font-semibold text-white"
            >
              <Sparkles size={15} /> Sample Token
            </button>
          </div>
        </div>
      )}
    </header>
  );
}
