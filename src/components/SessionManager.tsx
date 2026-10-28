import { useEffect, useMemo, useState } from "react";
import {
  Database,
  Cookie,
  Trash2,
  Plus,
  Copy,
  Check,
  ShieldCheck,
  ShieldAlert,
  HardDrive,
  RefreshCw,
  Download,
  KeyRound,
  Lock,
} from "lucide-react";
import { byteSize, getTokenStatus, parseJwt } from "../utils/jwt";
import { cn } from "../utils/cn";

export interface SessionEntry {
  id: string;
  key: string;
  token: string;
  origin: "localStorage" | "cookie" | "memory";
  secure: boolean;
  httpOnly: boolean;
  sameSite: "Strict" | "Lax" | "None";
  createdAt: number;
}

const LS_PREFIX = "authpulse:";

function readLocalStorage(): { key: string; value: string }[] {
  const out: { key: string; value: string }[] = [];
  try {
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k && k.startsWith(LS_PREFIX)) out.push({ key: k, value: localStorage.getItem(k) ?? "" });
    }
  } catch {}
  return out;
}

function readCookies(): { key: string; value: string }[] {
  try {
    return document.cookie
      .split(";")
      .map((c) => c.trim())
      .filter(Boolean)
      .map((c) => {
        const eq = c.indexOf("=");
        return eq === -1 ? { key: c, value: "" } : { key: c.slice(0, eq), value: decodeURIComponent(c.slice(eq + 1)) };
      })
      .filter((c) => c.key.toLowerCase().includes("auth") || c.key.toLowerCase().includes("session") || c.key.toLowerCase().includes("token"));
  } catch {
    return [];
  }
}

export default function SessionManager({
  entries,
  setEntries,
  currentToken,
  onLoad,
}: {
  entries: SessionEntry[];
  setEntries: React.Dispatch<React.SetStateAction<SessionEntry[]>>;
  currentToken: string;
  onLoad: (token: string) => void;
}) {
  const [copied, setCopied] = useState<string | null>(null);
  const [filter, setFilter] = useState<"all" | "localStorage" | "cookie" | "memory">("all");
  const [newKey, setNewKey] = useState("authpulse:session:custom");
  const [showAdd, setShowAdd] = useState(false);

  // hydrate from real browser storage on mount
  useEffect(() => {
    const ls = readLocalStorage();
    const ck = readCookies();
    if (ls.length === 0 && ck.length === 0) return;
    setEntries((prev: any) => {
      const existing = new Set(prev.map((e: SessionEntry) => e.key));
      const add: SessionEntry[] = [];
      ls.forEach(({ key, value }, i) => {
        if (!existing.has(key))
          add.push({ id: `ls-${i}-${Date.now()}`, key, token: value, origin: "localStorage", secure: location.protocol === "https:", httpOnly: false, sameSite: "Lax", createdAt: Date.now() });
      });
      ck.forEach(({ key, value }, i) => {
        if (!existing.has(key))
          add.push({ id: `ck-${i}-${Date.now()}`, key, token: value, origin: "cookie", secure: true, httpOnly: true, sameSite: "Strict", createdAt: Date.now() });
      });
      return [...prev, ...add];
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const filtered = useMemo(
    () => (filter === "all" ? entries : entries.filter((e) => e.origin === filter)),
    [entries, filter]
  );

  const totalBytes = useMemo(() => entries.reduce((a, e) => a + byteSize(e.key) + byteSize(e.token), 0), [entries]);
  const quota = 5 * 1024 * 1024; // 5MB typical LS quota

  const copy = async (t: string, id: string) => {
    try {
      await navigator.clipboard.writeText(t);
      setCopied(id);
      setTimeout(() => setCopied(null), 1500);
    } catch {}
  };

  const remove = (id: string) => {
    const e = entries.find((x) => x.id === id);
    if (e?.origin === "localStorage") {
      try {
        localStorage.removeItem(e.key);
      } catch {}
    }
    if (e?.origin === "cookie") {
      document.cookie = `${e.key}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/`;
    }
    setEntries(entries.filter((x) => x.id !== id));
  };

  const clearAll = () => {
    entries.forEach((e) => {
      if (e.origin === "localStorage") {
        try {
          localStorage.removeItem(e.key);
        } catch {}
      }
      if (e.origin === "cookie") document.cookie = `${e.key}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/`;
    });
    setEntries([]);
  };

  const persistCurrent = (origin: "localStorage" | "cookie") => {
    if (!currentToken.trim()) return;
    const key = newKey.trim() || `authpulse:session:${Date.now()}`;
    if (origin === "localStorage") {
      try {
        localStorage.setItem(key, currentToken.trim());
      } catch {}
    } else {
      document.cookie = `${key}=${encodeURIComponent(currentToken.trim().slice(0, 3800))}; path=/; SameSite=Lax${location.protocol === "https:" ? "; Secure" : ""}`;
    }
    setEntries([
      ...entries,
      {
        id: `${Date.now()}`,
        key,
        token: currentToken.trim(),
        origin,
        secure: location.protocol === "https:",
        httpOnly: origin === "cookie",
        sameSite: origin === "cookie" ? "Lax" : "Lax",
        createdAt: Date.now(),
      },
    ]);
    setShowAdd(false);
  };

  const exportJson = () => {
    const blob = new Blob([JSON.stringify(entries.map(({ token, ...rest }) => ({ ...rest, tokenPreview: token.slice(0, 40) + "…" })), null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "authpulse-sessions.json";
    a.click();
  };

  const refresh = () => {
    const ls = readLocalStorage();
    setEntries((prev: any) => {
      const mem = prev.filter((e: SessionEntry) => e.origin === "memory");
      const fresh: SessionEntry[] = ls.map(({ key, value }, i) => ({
        id: `ls-${i}`, key, token: value, origin: "localStorage" as const,
        secure: location.protocol === "https:", httpOnly: false, sameSite: "Lax" as const, createdAt: Date.now(),
      }));
      return [...fresh, ...mem];
    });
  };

  return (
    <div className="space-y-4">
      {/* Stats strip */}
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard icon={Database} label="Stored sessions" value={`${entries.length}`} sub={`${entries.filter((e) => e.origin === "localStorage").length} localStorage · ${entries.filter((e) => e.origin === "cookie").length} cookies · ${entries.filter((e) => e.origin === "memory").length} memory`} tone="indigo" />
        <StatCard icon={HardDrive} label="Storage used" value={`${(totalBytes / 1024).toFixed(2)} KB`} sub={`${((totalBytes / quota) * 100).toFixed(3)}% of ~5MB quota`} tone="emerald" progress={(totalBytes / quota) * 100} />
        <StatCard icon={ShieldCheck} label="Secure flagged" value={`${entries.filter((e) => e.secure).length}/${entries.length}`} sub="cookies with Secure attribute" tone="emerald" />
        <StatCard icon={ShieldAlert} label="XSS-exposed" value={`${entries.filter((e) => !e.httpOnly).length}`} sub="readable via document.* APIs" tone="amber" />
      </div>

      <div className="card overflow-hidden">
        <div className="flex flex-wrap items-center gap-2 border-b border-white/[0.06] px-4 py-3">
          <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-indigo-500/15 text-indigo-300">
            <Cookie size={15} />
          </div>
          <div className="mr-2">
            <h3 className="text-[13.5px] font-bold text-white">Storage & Cookie Inspector</h3>
            <p className="font-mono text-[10.5px] text-slate-500">keys · byte size · Secure / HttpOnly flags</p>
          </div>
          <div className="flex rounded-lg border border-white/10 bg-[#070b18] p-0.5 text-[11.5px] font-bold">
            {(["all", "localStorage", "cookie", "memory"] as const).map((f) => (
              <button key={f} onClick={() => setFilter(f)}
                className={cn("rounded-md px-2.5 py-1 transition-colors", filter === f ? "bg-indigo-600 text-white" : "text-slate-400 hover:text-white")}>
                {f === "all" ? "All" : f === "localStorage" ? "LS" : f === "cookie" ? "Cookies" : "Memory"}
              </button>
            ))}
          </div>
          <div className="flex-1" />
          <button onClick={refresh} className="flex items-center gap-1 rounded-lg border border-white/10 bg-white/[0.04] px-2.5 py-1.5 text-[12px] font-semibold text-slate-300 hover:text-white">
            <RefreshCw size={13} /> Re-scan
          </button>
          <button onClick={exportJson} disabled={entries.length === 0} className="flex items-center gap-1 rounded-lg border border-white/10 bg-white/[0.04] px-2.5 py-1.5 text-[12px] font-semibold text-slate-300 hover:text-white disabled:opacity-40">
            <Download size={13} /> Export
          </button>
          <button onClick={() => setShowAdd(!showAdd)} disabled={!currentToken.trim()}
            className="glow-indigo flex items-center gap-1 rounded-lg bg-gradient-to-r from-indigo-600 to-violet-600 px-2.5 py-1.5 text-[12px] font-bold text-white hover:brightness-110 disabled:opacity-40">
            <Plus size={13} /> Persist current token
          </button>
          <button onClick={clearAll} disabled={entries.length === 0} className="flex items-center gap-1 rounded-lg border border-rose-500/30 bg-rose-500/10 px-2.5 py-1.5 text-[12px] font-semibold text-rose-300 hover:bg-rose-500/20 disabled:opacity-40">
            <Trash2 size={13} /> Clear
          </button>
        </div>

        {showAdd && (
          <div className="flex flex-col gap-2 border-b border-white/[0.06] bg-indigo-500/[0.05] px-4 py-3 sm:flex-row sm:items-center animate-slide-up">
            <KeyRound size={15} className="hidden text-indigo-300 sm:block" />
            <input value={newKey} onChange={(e) => setNewKey(e.target.value)}
              className="flex-1 rounded-xl border border-white/10 bg-[#070b18] px-3 py-2 font-mono text-[12px] text-white outline-none focus:border-indigo-500/60" />
            <div className="flex gap-2">
              <button onClick={() => persistCurrent("localStorage")} className="flex-1 rounded-xl border border-indigo-500/40 bg-indigo-500/15 px-3 py-2 text-[12.5px] font-bold text-indigo-200 hover:bg-indigo-500/25 sm:flex-none">
                → localStorage
              </button>
              <button onClick={() => persistCurrent("cookie")} className="flex-1 rounded-xl border border-emerald-500/40 bg-emerald-500/10 px-3 py-2 text-[12.5px] font-bold text-emerald-200 hover:bg-emerald-500/20 sm:flex-none">
                → cookie
              </button>
            </div>
          </div>
        )}

        {/* Table */}
        <div className="overflow-x-auto">
          <table className="w-full min-w-[860px] text-left">
            <thead>
              <tr className="border-b border-white/[0.06] text-[10.5px] font-bold uppercase tracking-widest text-slate-500">
                <th className="px-4 py-2.5">Storage key</th>
                <th className="px-3 py-2.5">Origin</th>
                <th className="px-3 py-2.5">Token preview</th>
                <th className="px-3 py-2.5">Size</th>
                <th className="px-3 py-2.5">Flags</th>
                <th className="px-3 py-2.5">Status</th>
                <th className="px-3 py-2.5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-4 py-12 text-center">
                    <Cookie size={28} className="mx-auto text-slate-700" />
                    <p className="mt-2 text-[13.5px] font-semibold text-slate-300">No sessions in this view</p>
                    <p className="mx-auto mt-1 max-w-sm text-[12.5px] text-slate-500">
                      Decode a token, then use “Persist current token” to write it to localStorage or a cookie. Entries survive page reloads.
                    </p>
                  </td>
                </tr>
              ) : (
                filtered.map((e) => {
                  const d = parseJwt(e.token);
                  const st = getTokenStatus(d.payload);
                  const size = byteSize(e.token);
                  return (
                    <tr key={e.id} className="border-b border-white/[0.04] transition-colors last:border-0 hover:bg-white/[0.02]">
                      <td className="max-w-[220px] px-4 py-3">
                        <div className="truncate font-mono text-[12px] font-semibold text-indigo-200" title={e.key}>{e.key}</div>
                        <div className="font-mono text-[10.5px] text-slate-500">{new Date(e.createdAt).toLocaleTimeString()}</div>
                      </td>
                      <td className="px-3 py-3">
                        <span className={cn("inline-flex items-center gap-1 rounded-md px-2 py-0.5 font-mono text-[10.5px] font-bold",
                          e.origin === "localStorage" && "bg-indigo-500/10 text-indigo-300",
                          e.origin === "cookie" && "bg-amber-500/10 text-amber-300",
                          e.origin === "memory" && "bg-slate-500/10 text-slate-300")}>
                          {e.origin === "localStorage" ? <Database size={11} /> : e.origin === "cookie" ? <Cookie size={11} /> : <Lock size={11} />}
                          {e.origin}
                        </span>
                      </td>
                      <td className="max-w-[260px] px-3 py-3">
                        <div className="truncate font-mono text-[11.5px] text-slate-300" title={e.token}>
                          {d.isValidStructure ? (
                            <>
                              <span className="token-seg-header">{d.headerB64.slice(0, 10)}…</span>
                              <span className="text-slate-600">.</span>
                              <span className="token-seg-payload">{d.payloadB64.slice(0, 14)}…</span>
                            </>
                          ) : (
                            <span className="text-slate-500">{e.token.slice(0, 32)}…</span>
                          )}
                        </div>
                        <div className="font-mono text-[10.5px] text-slate-500">
                          {d.header?.alg ? `alg ${d.header.alg}` : "opaque / non-JWT"} · {d.payload?.sub ? `sub ${String(d.payload.sub).slice(0, 14)}` : "no sub"}
                        </div>
                      </td>
                      <td className="px-3 py-3 font-mono text-[12px] text-slate-200">
                        {size > 1024 ? `${(size / 1024).toFixed(1)} KB` : `${size} B`}
                      </td>
                      <td className="px-3 py-3">
                        <div className="flex flex-wrap gap-1">
                          <Flag on={e.secure} label="Secure" />
                          <Flag on={e.httpOnly} label="HttpOnly" />
                          <span className="rounded border border-white/10 bg-white/[0.04] px-1.5 py-0.5 font-mono text-[10px] text-slate-400">{e.sameSite}</span>
                        </div>
                      </td>
                      <td className="px-3 py-3">
                        <StatusDot state={st.state} />
                      </td>
                      <td className="px-3 py-3">
                        <div className="flex justify-end gap-1.5">
                          <button onClick={() => onLoad(e.token)} title="Load in decoder"
                            className="rounded-lg border border-indigo-500/30 bg-indigo-500/10 px-2 py-1.5 text-[11.5px] font-bold text-indigo-200 hover:bg-indigo-500/20">
                            Inspect
                          </button>
                          <button onClick={() => copy(e.token, e.id)} className="rounded-lg border border-white/10 bg-white/[0.04] p-1.5 text-slate-400 hover:text-white">
                            {copied === e.id ? <Check size={13} className="text-emerald-400" /> : <Copy size={13} />}
                          </button>
                          <button onClick={() => remove(e.id)} className="rounded-lg border border-white/10 bg-white/[0.04] p-1.5 text-slate-400 hover:border-rose-500/40 hover:text-rose-300">
                            <Trash2 size={13} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Guidance footer */}
        <div className="grid gap-2 border-t border-white/[0.06] bg-[#070b18]/60 px-4 py-3 text-[11.5px] leading-relaxed text-slate-400 md:grid-cols-3">
          <div className="flex gap-2"><ShieldCheck size={14} className="mt-0.5 shrink-0 text-emerald-400" /><span><b className="text-slate-200">HttpOnly + Secure + SameSite=Strict</b> is the safest cookie trio — immune to XSS theft.</span></div>
          <div className="flex gap-2"><ShieldAlert size={14} className="mt-0.5 shrink-0 text-amber-400" /><span><b className="text-slate-200">localStorage tokens</b> are convenient but readable by any script — keep TTLs short.</span></div>
          <div className="flex gap-2"><Lock size={14} className="mt-0.5 shrink-0 text-indigo-400" /><span><b className="text-slate-200">Memory-only</b> storage is safest for SPAs — cleared on reload, pair with silent refresh.</span></div>
        </div>
      </div>
    </div>
  );
}

function Flag({ on, label }: { on: boolean; label: string }) {
  return (
    <span className={cn("rounded border px-1.5 py-0.5 font-mono text-[10px] font-bold",
      on ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300" : "border-white/10 bg-white/[0.03] text-slate-600 line-through")}>
      {label}
    </span>
  );
}

function StatusDot({ state }: { state: string }) {
  const map: Record<string, { c: string; t: string }> = {
    valid: { c: "bg-emerald-400 text-emerald-300", t: "valid" },
    expiring: { c: "bg-amber-400 text-amber-300", t: "expiring" },
    expired: { c: "bg-rose-500 text-rose-300", t: "expired" },
    "no-exp": { c: "bg-amber-400 text-amber-300", t: "no exp" },
    unknown: { c: "bg-slate-500 text-slate-400", t: "unknown" },
    "not-yet": { c: "bg-indigo-400 text-indigo-300", t: "not yet" },
  };
  const m = map[state] ?? map.unknown;
  return (
    <span className={cn("inline-flex items-center gap-1.5 font-mono text-[11px] font-bold", m.t)}>
      <span className={cn("h-1.5 w-1.5 rounded-full", m.c.split(" ")[0])} /> {m.t}
    </span>
  );
}

function StatCard({ icon: Icon, label, value, sub, tone, progress }: { icon: any; label: string; value: string; sub: string; tone: "indigo" | "emerald" | "amber"; progress?: number }) {
  const tones = {
    indigo: "bg-indigo-500/15 text-indigo-300",
    emerald: "bg-emerald-500/15 text-emerald-300",
    amber: "bg-amber-500/15 text-amber-300",
  };
  return (
    <div className="card p-3.5">
      <div className="flex items-center gap-2.5">
        <div className={cn("flex h-8 w-8 items-center justify-center rounded-lg", tones[tone])}>
          <Icon size={16} />
        </div>
        <div className="text-[11px] font-bold uppercase tracking-widest text-slate-500">{label}</div>
      </div>
      <div className="mt-2 font-mono text-[21px] font-bold text-white">{value}</div>
      <div className="mt-0.5 text-[11.5px] text-slate-500">{sub}</div>
      {progress !== undefined && (
        <div className="mt-2 h-1 overflow-hidden rounded-full bg-white/[0.06]">
          <div className="h-full rounded-full bg-emerald-400" style={{ width: `${Math.max(2, Math.min(100, progress))}%` }} />
        </div>
      )}
    </div>
  );
}
