import { useEffect, useMemo, useRef, useState } from "react";
import {
  Braces,
  KeyRound,
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  Timer,
  Copy,
  Check,
  Eraser,
  Fingerprint,
  FileJson,
  Lock,
  Unlock,
  Eye,
  EyeOff,
  Save,
  AlertTriangle,
  CircleCheck,
  Hourglass,
  Scale,
  Hash,
  Zap,
} from "lucide-react";
import {
  parseJwt,
  getTokenStatus,
  formatUnix,
  formatUnixUTC,
  breakdownDuration,
  byteSize,
  verifyHS256,
} from "../utils/jwt";
import { DEFAULT_SECRET, type TokenFixture } from "../data/mockTokens";
import { JsonView, ClaimRow } from "./JsonView";
import { cn } from "../utils/cn";

interface Props {
  rawToken: string;
  setRawToken: (t: string) => void;
  fixtures: TokenFixture[];
  activeFixtureId: string | null;
  setActiveFixtureId: (id: string | null) => void;
  onSaveToSession: () => void;
}

function useNow(intervalMs = 1000) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), intervalMs);
    return () => clearInterval(t);
  }, [intervalMs]);
  return now;
}

export default function JwtDecoder({ rawToken, setRawToken, fixtures, activeFixtureId, setActiveFixtureId, onSaveToSession }: Props) {
  const [secret, setSecret] = useState(DEFAULT_SECRET);
  const [showSecret, setShowSecret] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [verifyResult, setVerifyResult] = useState<{ ok: boolean; reason: string; expected: string } | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const [payloadTab, setPayloadTab] = useState<"claims" | "json">("claims");
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  useNow();

  const decoded = useMemo(() => parseJwt(rawToken), [rawToken]);
  const status = useMemo(() => getTokenStatus(decoded.payload), [decoded.payload, rawToken, Date.now()]);
  // recompute status every render (useNow triggers render)

  useEffect(() => {
    setVerifyResult(null);
  }, [rawToken]);

  const doVerify = async () => {
    if (!decoded.isValidStructure) return;
    const alg = decoded.header?.alg;
    if (alg !== "HS256") {
      setVerifyResult({
        ok: false,
        expected: "",
        reason: alg === "RS256" || alg === "ES256" || alg === "PS256"
          ? "Asymmetric algorithm — verification requires the JWKS public key, not a shared secret."
          : `Algorithm ${alg ?? "unknown"} is not verifiable with HMAC.`,
      });
      return;
    }
    setVerifying(true);
    const res = await verifyHS256(decoded.raw, secret);
    setVerifyResult(res);
    setVerifying(false);
  };

  const copy = async (text: string, id: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(id);
      setTimeout(() => setCopied(null), 1600);
    } catch {}
  };

  const loadFixture = (f: TokenFixture) => {
    setActiveFixtureId(f.id);
    setRawToken(f.token);
    setVerifyResult(null);
  };

  const remaining = status.remainingSec ?? 0;
  const bd = breakdownDuration(remaining);
  const pct = status.percentElapsed ?? 0;
  const ringC = 2 * Math.PI * 34;
  const ringOffset = ringC * (1 - Math.min(1, Math.max(0, pct)));

  const statusBadge = (() => {
    if (!rawToken.trim())
      return { label: "No Token", cls: "border-slate-500/30 bg-slate-500/10 text-slate-300", icon: Fingerprint };
    if (!decoded.isValidStructure)
      return { label: "Malformed Token", cls: "border-rose-500/30 bg-rose-500/10 text-rose-300", icon: ShieldX };
    if (status.state === "expired")
      return { label: "Expired Token", cls: "border-rose-500/40 bg-rose-500/15 text-rose-300", icon: ShieldX };
    if (verifyResult?.ok)
      return { label: "Signature Verified", cls: "border-emerald-400/40 bg-emerald-400/15 text-emerald-300", icon: ShieldCheck };
    if (verifyResult && !verifyResult.ok && decoded.header?.alg === "HS256")
      return { label: "Invalid Signature", cls: "border-rose-500/40 bg-rose-500/15 text-rose-300", icon: ShieldAlert };
    if (status.state === "expiring")
      return { label: "Expiring Soon", cls: "border-amber-400/40 bg-amber-400/15 text-amber-300", icon: Hourglass };
    if (status.state === "valid")
      return { label: "Structurally Valid", cls: "border-indigo-400/40 bg-indigo-400/15 text-indigo-300", icon: CircleCheck };
    if (status.state === "no-exp")
      return { label: "No Expiry Claim", cls: "border-amber-400/40 bg-amber-400/15 text-amber-300", icon: AlertTriangle };
    return { label: "Unknown State", cls: "border-slate-500/30 bg-slate-500/10 text-slate-300", icon: Fingerprint };
  })();

  const BadgeIcon = statusBadge.icon;

  const payloadEntries = decoded.payload ? Object.entries(decoded.payload) : [];
  const stdClaims = ["sub", "iss", "aud", "exp", "iat", "nbf", "jti"];
  const customClaims = payloadEntries.filter(([k]) => !stdClaims.includes(k));

  return (
    <div className="space-y-4">
      {/* Fixture switcher */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="mr-1 flex items-center gap-1.5 text-[11px] font-bold uppercase tracking-widest text-slate-500">
          <Zap size={13} className="text-amber-400" /> Test fixtures
        </span>
        {fixtures.map((f) => (
          <button
            key={f.id}
            onClick={() => loadFixture(f)}
            className={cn(
              "group flex items-center gap-2 rounded-xl border px-3 py-1.5 text-[12.5px] font-semibold transition-all",
              activeFixtureId === f.id
                ? "border-indigo-500/60 bg-indigo-500/15 text-white shadow-lg shadow-indigo-950/50"
                : "border-white/10 bg-white/[0.03] text-slate-300 hover:border-indigo-500/40 hover:text-white"
            )}
          >
            <span
              className={cn(
                "h-1.5 w-1.5 rounded-full",
                f.tagColor === "emerald" && "bg-emerald-400",
                f.tagColor === "indigo" && "bg-indigo-400",
                f.tagColor === "rose" && "bg-rose-400"
              )}
            />
            {f.name}
            <span className="hidden font-mono text-[10px] font-normal text-slate-500 group-hover:text-slate-400 lg:inline">
              {f.tag}
            </span>
          </button>
        ))}
        <div className="flex-1" />
        <div
          className={cn(
            "flex items-center gap-1.5 rounded-xl border px-3 py-1.5 text-[12.5px] font-bold",
            statusBadge.cls
          )}
        >
          <BadgeIcon size={15} />
          {statusBadge.label}
        </div>
      </div>

      {/* Input + Countdown row */}
      <div className="grid gap-4 xl:grid-cols-3">
        {/* Raw token input */}
        <div className="card relative overflow-hidden xl:col-span-2">
          <div className="flex items-center gap-2 border-b border-white/[0.06] px-4 py-3">
            <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-indigo-500/15 text-indigo-300">
              <Braces size={15} />
            </div>
            <div>
              <h3 className="text-[13.5px] font-bold text-white">Raw Token Input</h3>
              <p className="font-mono text-[10.5px] text-slate-500">paste JWT · auto-decodes header.payload.signature</p>
            </div>
            <div className="flex-1" />
            <button
              onClick={() => copy(decoded.raw, "raw")}
              className="flex items-center gap-1 rounded-lg border border-white/10 bg-white/[0.04] px-2 py-1 text-[11.5px] font-semibold text-slate-300 hover:border-indigo-500/40 hover:text-white"
            >
              {copied === "raw" ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
              {copied === "raw" ? "Copied" : "Copy"}
            </button>
            <button
              onClick={() => {
                setRawToken("");
                setActiveFixtureId(null);
                setVerifyResult(null);
              }}
              className="flex items-center gap-1 rounded-lg border border-white/10 bg-white/[0.04] px-2 py-1 text-[11.5px] font-semibold text-slate-300 hover:border-rose-500/40 hover:text-rose-300"
            >
              <Eraser size={12} /> Clear
            </button>
            <button
              onClick={onSaveToSession}
              disabled={!decoded.isValidStructure}
              className="hidden items-center gap-1 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-2 py-1 text-[11.5px] font-semibold text-emerald-300 hover:bg-emerald-500/20 disabled:opacity-40 sm:flex"
            >
              <Save size={12} /> Save to Session
            </button>
          </div>
          <div className="p-4">
            <textarea
              ref={textareaRef}
              value={rawToken}
              onChange={(e) => {
                setRawToken(e.target.value);
                setActiveFixtureId(null);
              }}
              spellCheck={false}
              placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwi..."
              className="h-32 w-full resize-y rounded-xl border border-white/10 bg-[#070b18] p-3 font-mono text-[12px] leading-relaxed text-slate-200 outline-none transition-colors placeholder:text-slate-600 focus:border-indigo-500/60 focus:ring-2 focus:ring-indigo-500/20"
            />
            {/* Segment visualizer */}
            {decoded.isValidStructure ? (
              <div className="mt-3 overflow-hidden rounded-xl border border-white/[0.07] bg-[#070b18]">
                <div className="flex items-center gap-3 border-b border-white/[0.06] px-3 py-1.5">
                  <span className="font-mono text-[10px] font-bold uppercase tracking-wider text-slate-500">Segments</span>
                  <span className="flex items-center gap-1 font-mono text-[10px]"><span className="h-2 w-2 rounded-sm bg-rose-400/80" /> header</span>
                  <span className="flex items-center gap-1 font-mono text-[10px]"><span className="h-2 w-2 rounded-sm bg-violet-400/80" /> payload</span>
                  <span className="flex items-center gap-1 font-mono text-[10px]"><span className="h-2 w-2 rounded-sm bg-teal-300/80" /> signature</span>
                  <div className="flex-1" />
                  <span className="font-mono text-[10px] text-slate-500">{byteSize(decoded.raw)} bytes · {decoded.raw.length} chars</span>
                </div>
                <div className="break-all px-3 py-2.5 font-mono text-[11.5px] leading-relaxed">
                  <span className="token-seg-header">{decoded.headerB64}</span>
                  <span className="text-slate-600">.</span>
                  <span className="token-seg-payload">{decoded.payloadB64}</span>
                  <span className="text-slate-600">.</span>
                  <span className="token-seg-signature">{decoded.signatureB64}</span>
                  <span className="animate-caret ml-0.5 inline-block h-3.5 w-[7px] translate-y-[3px] bg-indigo-400/80" />
                </div>
              </div>
            ) : rawToken.trim() ? (
              <div className="mt-3 flex items-center gap-2 rounded-xl border border-rose-500/25 bg-rose-500/[0.07] px-3 py-2.5 text-[12.5px] text-rose-300">
                <AlertTriangle size={15} className="shrink-0" />
                Expected 3 dot-separated segments — found {decoded.parts || 0}. Tokens look like <span className="font-mono text-[11px]">header.payload.signature</span>
              </div>
            ) : (
              <div className="mt-3 flex items-center gap-2 rounded-xl border border-dashed border-white/10 px-3 py-2.5 text-[12.5px] text-slate-500">
                <Fingerprint size={15} className="shrink-0 text-indigo-400" />
                Awaiting token — pick a test fixture above or paste any JWT to inspect it live.
              </div>
            )}
          </div>
        </div>

        {/* Countdown */}
        <div className="card relative overflow-hidden">
          <div className="pointer-events-none absolute -right-16 -top-16 h-48 w-48 rounded-full bg-indigo-600/20 blur-3xl" />
          <div className="flex items-center gap-2 border-b border-white/[0.06] px-4 py-3">
            <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-amber-500/15 text-amber-300">
              <Timer size={15} />
            </div>
            <div>
              <h3 className="text-[13.5px] font-bold text-white">Live Expiration Countdown</h3>
              <p className="font-mono text-[10.5px] text-slate-500">derived from `exp` claim</p>
            </div>
          </div>
          <div className="flex flex-col items-center px-4 py-5">
            {/* ring */}
            <div className="relative h-[132px] w-[132px]">
              <svg viewBox="0 0 84 84" className="h-full w-full -rotate-90">
                <circle cx="42" cy="42" r="34" fill="none" stroke="rgba(255,255,255,0.07)" strokeWidth="7" />
                <circle
                  cx="42" cy="42" r="34" fill="none"
                  stroke={status.state === "expired" ? "#f43f5e" : status.state === "expiring" ? "#f59e0b" : status.state === "valid" ? "#10b981" : "#475569"}
                  strokeWidth="7" strokeLinecap="round"
                  strokeDasharray={ringC} strokeDashoffset={ringOffset}
                  style={{ transition: "stroke-dashoffset 1s linear, stroke .3s", filter: `drop-shadow(0 0 6px ${status.state === "expired" ? "#f43f5e66" : status.state === "expiring" ? "#f59e0b66" : "#10b98166"})` }}
                />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                {status.state === "valid" || status.state === "expiring" ? (
                  <>
                    <div className="font-mono text-[19px] font-bold leading-none text-white">
                      {String(bd.hours + bd.days * 24).padStart(2, "0")}:{String(bd.minutes).padStart(2, "0")}:{String(bd.seconds).padStart(2, "0")}
                    </div>
                    <div className="mt-1 text-[10px] font-bold uppercase tracking-widest text-slate-500">remaining</div>
                  </>
                ) : status.state === "expired" ? (
                  <>
                    <ShieldX size={26} className="text-rose-400" />
                    <div className="mt-1 text-[11px] font-bold uppercase tracking-widest text-rose-400">Expired</div>
                  </>
                ) : status.state === "no-exp" ? (
                  <>
                    <Hourglass size={24} className="text-amber-400" />
                    <div className="mt-1 px-2 text-center text-[10px] font-bold uppercase tracking-widest text-amber-400">Never expires</div>
                  </>
                ) : (
                  <>
                    <Fingerprint size={24} className="text-slate-600" />
                    <div className="mt-1 text-[10px] font-bold uppercase tracking-widest text-slate-600">No data</div>
                  </>
                )}
              </div>
            </div>

            {/* digit boxes */}
            <div className="mt-4 grid w-full grid-cols-4 gap-2">
              {[
                { v: bd.days, l: "days" },
                { v: bd.hours, l: "hrs" },
                { v: bd.minutes, l: "min" },
                { v: bd.seconds, l: "sec" },
              ].map((d) => (
                <div key={d.l} className="rounded-xl border border-white/[0.07] bg-[#070b18] py-2 text-center">
                  <div className={cn("font-mono text-[17px] font-bold", status.state === "expired" ? "text-rose-400" : "text-white")}>
                    {String(d.v).padStart(2, "0")}
                  </div>
                  <div className="text-[9.5px] font-bold uppercase tracking-widest text-slate-500">{d.l}</div>
                </div>
              ))}
            </div>

            <div className="mt-3 w-full space-y-1.5 font-mono text-[11px]">
              <div className="flex justify-between"><span className="text-slate-500">issued (iat)</span><span className="text-slate-300">{formatUnix(decoded.payload?.iat)}</span></div>
              <div className="flex justify-between"><span className="text-slate-500">expires (exp)</span><span className={status.state === "expired" ? "text-rose-300" : "text-emerald-300"}>{formatUnix(decoded.payload?.exp)}</span></div>
            </div>
            {/* progress bar */}
            <div className="mt-3 h-1.5 w-full overflow-hidden rounded-full bg-white/[0.06]">
              <div
                className={cn("h-full rounded-full transition-all duration-1000", status.state === "expired" ? "bg-rose-500" : status.state === "expiring" ? "bg-amber-400" : "bg-gradient-to-r from-indigo-500 to-emerald-400")}
                style={{ width: `${Math.round((status.percentElapsed ?? 0) * 100)}%` }}
              />
            </div>
            <div className="mt-1 flex w-full justify-between font-mono text-[10px] text-slate-500">
              <span>session elapsed {Math.round((status.percentElapsed ?? 0) * 100)}%</span>
              <span>{status.totalLifespanSec ? `TTL ${(status.totalLifespanSec / 3600).toFixed(1)}h` : ""}</span>
            </div>
          </div>
        </div>
      </div>

      {/* 3-panel breakdown */}
      <div className="grid gap-4 lg:grid-cols-2 xl:grid-cols-3">
        {/* Header panel */}
        <div className="card overflow-hidden">
          <div className="flex items-center gap-2 border-b border-white/[0.06] px-4 py-3">
            <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-rose-500/15 text-rose-300">
              <FileJson size={15} />
            </div>
            <div>
              <h3 className="text-[13.5px] font-bold text-white">Header <span className="font-mono font-normal text-slate-500">· JOSE</span></h3>
              <p className="font-mono text-[10.5px] text-slate-500">algorithm & token type</p>
            </div>
            <div className="flex-1" />
            <button onClick={() => decoded.header && copy(JSON.stringify(decoded.header, null, 2), "hdr")} className="rounded-lg border border-white/10 bg-white/[0.04] p-1.5 text-slate-400 hover:text-white">
              {copied === "hdr" ? <Check size={13} className="text-emerald-400" /> : <Copy size={13} />}
            </button>
          </div>
          {decoded.header ? (
            <div>
              <div className="flex flex-wrap gap-2 px-4 pt-3">
                <span className="flex items-center gap-1.5 rounded-lg border border-indigo-500/30 bg-indigo-500/10 px-2.5 py-1 font-mono text-[11.5px] font-bold text-indigo-300">
                  <Lock size={12} /> alg: {decoded.header.alg ?? "—"}
                </span>
                <span className="flex items-center gap-1.5 rounded-lg border border-white/10 bg-white/[0.04] px-2.5 py-1 font-mono text-[11.5px] text-slate-300">
                  typ: {decoded.header.typ ?? "—"}
                </span>
                {decoded.header.kid && (
                  <span className="flex items-center gap-1.5 rounded-lg border border-white/10 bg-white/[0.04] px-2.5 py-1 font-mono text-[11.5px] text-slate-300">
                    <Hash size={12} className="text-slate-500" /> kid: {decoded.header.kid}
                  </span>
                )}
              </div>
              <div className="m-3 rounded-xl border border-white/[0.07] bg-[#070b18] p-3">
                <JsonView data={decoded.header} />
              </div>
              <div className="space-y-0 border-t border-white/[0.06]">
                <ClaimRow label="Algorithm" value={decoded.header.alg ?? "—"} accent={decoded.header.alg === "none" ? "#f43f5e" : "#a5b4fc"} sub={decoded.header.alg === "HS256" ? "Symmetric HMAC-SHA256" : decoded.header.alg === "RS256" ? "Asymmetric RSA + SHA256" : undefined} />
                <ClaimRow label="Token Type" value={decoded.header.typ ?? "—"} />
                <ClaimRow label="Key ID" value={decoded.header.kid ?? "—"} sub="Selects verification key in JWKS" />
              </div>
            </div>
          ) : (
            <EmptyPanel text={decoded.headerError ?? "No header decoded yet"} />
          )}
        </div>

        {/* Payload panel */}
        <div className="card overflow-hidden">
          <div className="flex items-center gap-2 border-b border-white/[0.06] px-4 py-3">
            <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-violet-500/15 text-violet-300">
              <Scale size={15} />
            </div>
            <div>
              <h3 className="text-[13.5px] font-bold text-white">Payload Claims</h3>
              <p className="font-mono text-[10.5px] text-slate-500">{payloadEntries.length} claims · registered + custom</p>
            </div>
            <div className="flex-1" />
            <div className="flex rounded-lg border border-white/10 bg-[#070b18] p-0.5 text-[11px] font-bold">
              {(["claims", "json"] as const).map((t) => (
                <button key={t} onClick={() => setPayloadTab(t)} className={cn("rounded-md px-2.5 py-1 uppercase tracking-wide transition-colors", payloadTab === t ? "bg-indigo-600 text-white" : "text-slate-400 hover:text-white")}>
                  {t}
                </button>
              ))}
            </div>
          </div>
          {decoded.payload ? (
            payloadTab === "claims" ? (
              <div className="max-h-[380px] overflow-y-auto">
                <div className="px-3 pb-1 pt-2 text-[10px] font-bold uppercase tracking-widest text-slate-500">Registered claims</div>
                <div className="border-y border-white/[0.06]">
                  <ClaimRow label="sub · Subject" value={decoded.payload.sub ?? "—"} accent="#6ee7b7" />
                  <ClaimRow label="iss · Issuer" value={decoded.payload.iss ?? "—"} />
                  <ClaimRow label="aud · Audience" value={Array.isArray(decoded.payload.aud) ? decoded.payload.aud.join(", ") : (decoded.payload.aud ?? "—")} accent="#fcd34d" />
                  <ClaimRow label="exp · Expires" value={decoded.payload.exp != null ? `${decoded.payload.exp}` : "—"} sub={formatUnixUTC(decoded.payload.exp)} accent={status.state === "expired" ? "#fda4af" : "#6ee7b7"} />
                  <ClaimRow label="iat · Issued At" value={decoded.payload.iat != null ? `${decoded.payload.iat}` : "—"} sub={formatUnixUTC(decoded.payload.iat)} />
                  {decoded.payload.nbf != null && <ClaimRow label="nbf · Not Before" value={`${decoded.payload.nbf}`} sub={formatUnixUTC(decoded.payload.nbf)} />}
                  {decoded.payload.jti && <ClaimRow label="jti · Token ID" value={decoded.payload.jti} />}
                </div>
                {customClaims.length > 0 && (
                  <>
                    <div className="px-3 pb-1 pt-2 text-[10px] font-bold uppercase tracking-widest text-slate-500">Custom / private claims</div>
                    <div className="border-b border-white/[0.06]">
                      {customClaims.map(([k, v]) => (
                        <ClaimRow key={k} label={k} value={typeof v === "object" ? JSON.stringify(v) : String(v)} accent="#c4b5fd" />
                      ))}
                    </div>
                  </>
                )}
              </div>
            ) : (
              <div className="m-3 max-h-[330px] overflow-y-auto rounded-xl border border-white/[0.07] bg-[#070b18] p-3">
                <JsonView data={decoded.payload} />
              </div>
            )
          ) : (
            <EmptyPanel text={decoded.payloadError ?? "No payload decoded yet"} />
          )}
        </div>

        {/* Signature panel */}
        <div className="card overflow-hidden lg:col-span-2 xl:col-span-1">
          <div className="flex items-center gap-2 border-b border-white/[0.06] px-4 py-3">
            <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-teal-500/15 text-teal-300">
              <KeyRound size={15} />
            </div>
            <div>
              <h3 className="text-[13.5px] font-bold text-white">Signature Verification</h3>
              <p className="font-mono text-[10.5px] text-slate-500">HMAC · JWKS · integrity</p>
            </div>
          </div>
          <div className="space-y-3 p-4">
            {/* status banner */}
            <div className={cn("flex items-start gap-2.5 rounded-xl border px-3 py-2.5", statusBadge.cls)}>
              <BadgeIcon size={17} className="mt-0.5 shrink-0" />
              <div className="min-w-0">
                <div className="text-[13px] font-bold">{statusBadge.label}</div>
                <div className="mt-0.5 text-[11.5px] opacity-80">
                  {verifyResult
                    ? verifyResult.reason
                    : decoded.header?.alg === "RS256"
                    ? "RS256 uses an RSA private key to sign. Paste the JWKS public key or x5c certificate to verify out-of-band."
                    : decoded.header?.alg === "HS256"
                    ? "Provide the shared secret and run verification to cryptographically confirm integrity."
                    : "Decode a token to begin verification."}
                </div>
              </div>
            </div>

            {/* alg info */}
            <div className="grid grid-cols-2 gap-2">
              <div className="rounded-xl border border-white/[0.07] bg-[#070b18] px-3 py-2">
                <div className="text-[10px] font-bold uppercase tracking-widest text-slate-500">Algorithm</div>
                <div className="mt-0.5 font-mono text-[14px] font-bold text-white">{decoded.header?.alg ?? "—"}</div>
              </div>
              <div className="rounded-xl border border-white/[0.07] bg-[#070b18] px-3 py-2">
                <div className="text-[10px] font-bold uppercase tracking-widest text-slate-500">Sig length</div>
                <div className="mt-0.5 font-mono text-[14px] font-bold text-white">{decoded.signatureB64 ? `${decoded.signatureB64.length} chars` : "—"}</div>
              </div>
            </div>

            {/* signature preview */}
            <div className="rounded-xl border border-white/[0.07] bg-[#070b18] p-3">
              <div className="mb-1 flex items-center justify-between">
                <span className="text-[10px] font-bold uppercase tracking-widest text-slate-500">Signature segment</span>
                <button onClick={() => decoded.signatureB64 && copy(decoded.signatureB64, "sig")} className="text-slate-500 hover:text-white">
                  {copied === "sig" ? <Check size={13} className="text-emerald-400" /> : <Copy size={13} />}
                </button>
              </div>
              <div className="break-all font-mono text-[11px] leading-relaxed text-teal-200/90">
                {decoded.signatureB64 || <span className="text-slate-600">—</span>}
              </div>
            </div>

            {/* secret input */}
            <div>
              <label className="mb-1.5 flex items-center gap-1.5 text-[11px] font-bold uppercase tracking-widest text-slate-500">
                {showSecret ? <Unlock size={12} /> : <Lock size={12} />} HMAC shared secret
              </label>
              <div className="flex gap-2">
                <div className="relative flex-1">
                  <input
                    type={showSecret ? "text" : "password"}
                    value={secret}
                    onChange={(e) => setSecret(e.target.value)}
                    placeholder="your-256-bit-secret"
                    className="w-full rounded-xl border border-white/10 bg-[#070b18] py-2.5 pl-3 pr-10 font-mono text-[12.5px] text-white outline-none placeholder:text-slate-600 focus:border-indigo-500/60 focus:ring-2 focus:ring-indigo-500/20"
                  />
                  <button onClick={() => setShowSecret(!showSecret)} className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-white">
                    {showSecret ? <EyeOff size={15} /> : <Eye size={15} />}
                  </button>
                </div>
                <button
                  onClick={doVerify}
                  disabled={!decoded.isValidStructure || verifying || !secret}
                  className="glow-indigo flex items-center gap-1.5 rounded-xl bg-gradient-to-r from-indigo-600 to-violet-600 px-4 text-[13px] font-bold text-white transition-all hover:brightness-110 disabled:opacity-40"
                >
                  {verifying ? <span className="h-4 w-4 animate-spin rounded-full border-2 border-white/30 border-t-white" /> : <ShieldCheck size={15} />}
                  Verify
                </button>
              </div>
              <p className="mt-1.5 font-mono text-[10.5px] leading-relaxed text-slate-500">
                Fixtures are signed with <button onClick={() => setSecret(DEFAULT_SECRET)} className="text-indigo-300 underline decoration-dotted hover:text-indigo-200">dev secret — click to fill</button>. RS256 fixtures need JWKS.
              </p>
            </div>

            {verifyResult?.expected && decoded.header?.alg === "HS256" && (
              <div className="rounded-xl border border-white/[0.07] bg-[#070b18] p-3">
                <div className="mb-1 text-[10px] font-bold uppercase tracking-widest text-slate-500">Computed signature</div>
                <div className={cn("break-all font-mono text-[11px] leading-relaxed", verifyResult.ok ? "text-emerald-300" : "text-rose-300")}>
                  {verifyResult.expected}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function EmptyPanel({ text }: { text: string }) {
  return (
    <div className="flex h-48 flex-col items-center justify-center gap-2 p-6 text-center">
      <Fingerprint size={26} className="text-slate-700" />
      <p className="max-w-[220px] text-[12.5px] text-slate-500">{text}</p>
    </div>
  );
}
