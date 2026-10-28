import { useMemo } from "react";
import {
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  Info,
  ChevronRight,
  Gauge,
  ListChecks,
  Lightbulb,
  KeyRound,
  Clock,
  Globe,
} from "lucide-react";
import { getTokenStatus, parseJwt } from "../utils/jwt";
import { cn } from "../utils/cn";

export interface Check {
  id: string;
  severity: "critical" | "warning" | "pass" | "info";
  title: string;
  detail: string;
  fix: string;
  category: string;
}

export function runChecks(token: string, issuer: string): { checks: Check[]; score: number } {
  const d = parseJwt(token);
  const checks: Check[] = [];

  if (!token.trim()) {
    return {
      score: 0,
      checks: [
        { id: "empty", severity: "info", title: "No token loaded", detail: "Paste a JWT in the Inspector or import a fixture to run the health audit.", fix: "Load any token to begin — the audit updates live.", category: "Overview" },
      ],
    };
  }
  if (!d.isValidStructure) {
    return {
      score: 5,
      checks: [
        { id: "malformed", severity: "critical", title: "Token is malformed", detail: d.headerError ?? d.payloadError ?? `Found ${d.parts} segments, expected 3.`, fix: "Ensure the token is complete — header.payload.signature with no whitespace or truncation.", category: "Structure" },
      ],
    };
  }

  const h = d.header!;
  const p = d.payload!;
  const st = getTokenStatus(p);

  // 1. alg none
  if (String(h.alg).toLowerCase() === "none") {
    checks.push({ id: "alg-none", severity: "critical", title: "Critical: algorithm is 'none'", detail: "Token explicitly opts out of signature verification. Any attacker can forge arbitrary claims.", fix: "Reject alg=none unconditionally server-side; enforce an allow-list like [RS256, ES256].", category: "Signature" });
  } else if (h.alg === "HS256") {
    checks.push({ id: "alg-hs", severity: "warning", title: "Algorithm is symmetric HS256", detail: "HMAC uses one shared secret — anyone holding it can both verify and mint tokens. Secret rotation is painful at scale.", fix: "Prefer RS256/ES256 with JWKS rotation for multi-service or public-client architectures.", category: "Signature" });
  } else if (h.alg === "RS256" || h.alg === "ES256" || h.alg === "PS256") {
    checks.push({ id: "alg-asym", severity: "pass", title: `Strong asymmetric algorithm (${h.alg})`, detail: "Private-key signing with public verification enables safe key distribution and rotation via JWKS.", fix: "Keep the JWKS endpoint cached with a short TTL and pin the kid to the active rotation.", category: "Signature" });
  } else {
    checks.push({ id: "alg-other", severity: "warning", title: `Uncommon algorithm: ${h.alg ?? "missing"}`, detail: "Non-standard algorithms may lack library support or security review.", fix: "Standardize on RS256, ES256 or EdDSA across all issuers.", category: "Signature" });
  }

  // 2. typ
  if (!h.typ) checks.push({ id: "typ", severity: "info", title: "Header lacks explicit typ: JWT", detail: "Missing type hint can confuse generic JOSE parsers.", fix: "Set typ to JWT (or at+jwt for OAuth access tokens).", category: "Structure" });
  else checks.push({ id: "typ", severity: "pass", title: `Token type declared (${h.typ})`, detail: "Explicit typ helps parsers and gateways route verification correctly.", fix: "No action needed.", category: "Structure" });

  // 3. kid
  if (!h.kid) checks.push({ id: "kid", severity: "warning", title: "No key ID (kid) in header", detail: "Without kid the verifier cannot select the right key during rotation — deployments must hard-stop instead of rolling.", fix: "Add kid pointing at the JWKS entry; rotate by publishing new kid before switching signers.", category: "Key Mgmt" });
  else checks.push({ id: "kid", severity: "pass", title: `Key ID present (${h.kid})`, detail: "Verifier can pin and rotate keys cleanly.", fix: "No action needed.", category: "Key Mgmt" });

  // 4. exp
  if (p.exp == null) {
    checks.push({ id: "exp-missing", severity: "critical", title: "Missing expiration (exp) claim", detail: "Token never expires — a single leak grants indefinite access with no revocation path.", fix: "Add exp with a short TTL (5–60 min for access tokens) plus refresh-token rotation.", category: "Lifetime" });
  } else if (st.state === "expired") {
    checks.push({ id: "exp-past", severity: "critical", title: "Token is expired", detail: `exp was ${Math.abs(st.remainingSec ?? 0)}s ago. Verifiers must reject this token.`, fix: "Trigger the refresh flow or re-authenticate; never extend exp client-side.", category: "Lifetime" });
  } else {
    const ttl = st.totalLifespanSec ?? 0;
    if (ttl > 86400) checks.push({ id: "exp-long", severity: "warning", title: `Long-lived token (TTL ${(ttl / 3600).toFixed(1)}h)`, detail: "Lifetimes over 24h widen the blast radius of theft and delay revocation.", fix: "Shrink access-token TTL under 1h; move longevity to rotating refresh tokens.", category: "Lifetime" });
    else if (st.state === "expiring") checks.push({ id: "exp-soon", severity: "warning", title: "Token expires within 5 minutes", detail: "Clients should refresh proactively to avoid mid-request 401s.", fix: "Refresh when <10% of TTL remains or on first 401 with retry-once.", category: "Lifetime" });
    else checks.push({ id: "exp-ok", severity: "pass", title: `Healthy lifetime (TTL ${(ttl / 3600).toFixed(1)}h)`, detail: "Expiry is present, in the future, and reasonably scoped.", fix: "No action needed.", category: "Lifetime" });
  }

  // 5. aud
  if (p.aud == null || p.aud === "") {
    checks.push({ id: "aud-missing", severity: "warning", title: "Warning: token lacks strict audience (aud) claim", detail: "Without aud, the token is accepted by any service trusting the issuer — a confused-deputy risk.", fix: "Set aud to the exact API identifier and validate it strictly on every service.", category: "Claims" });
  } else {
    const audStr = Array.isArray(p.aud) ? p.aud.join(", ") : String(p.aud);
    checks.push({ id: "aud-ok", severity: "pass", title: `Audience restricted (${audStr.slice(0, 42)}${audStr.length > 42 ? "…" : ""})`, detail: "Verifiers can reject tokens minted for other services.", fix: "No action needed.", category: "Claims" });
  }

  // 6. iss
  if (!p.iss) checks.push({ id: "iss-missing", severity: "warning", title: "Missing issuer (iss) claim", detail: "Verifiers cannot confirm which authority minted the token.", fix: "Set iss to the canonical issuer URL and allow-list it in verification.", category: "Claims" });
  else if (p.iss !== issuer) checks.push({ id: "iss-mismatch", severity: "warning", title: `Issuer differs from ${issuer}`, detail: `Token says iss=${p.iss}. Cross-environment tokens suggest env leakage or misconfiguration.`, fix: "Verify tokens only against the issuer of the active environment.", category: "Claims" });
  else checks.push({ id: "iss-ok", severity: "pass", title: "Issuer matches environment", detail: `${p.iss} is the expected authority for this workspace.`, fix: "No action needed.", category: "Claims" });

  // 7. sub
  if (!p.sub) checks.push({ id: "sub", severity: "warning", title: "Missing subject (sub) claim", detail: "No stable user identifier — audit trails and revocation lists cannot key on this token.", fix: "Always include an opaque, immutable sub.", category: "Claims" });
  else checks.push({ id: "sub", severity: "pass", title: "Subject present", detail: `sub=${p.sub} anchors identity and audit.`, fix: "No action needed.", category: "Claims" });

  // 8. iat / nbf
  if (p.iat == null) checks.push({ id: "iat", severity: "info", title: "No issued-at (iat) claim", detail: "Age-based policies (max_session_age) cannot be enforced.", fix: "Add iat at mint time.", category: "Lifetime" });
  if (p.nbf != null && st.state === "not-yet") checks.push({ id: "nbf", severity: "warning", title: "Token not valid yet (nbf in future)", detail: "Clock skew or premature use — verifiers will reject until nbf.", fix: "Allow ±60s leeway for clock skew.", category: "Lifetime" });

  // 9. jti
  if (!p.jti) checks.push({ id: "jti", severity: "info", title: "No JWT ID (jti) — revocation is hard", detail: "Without a unique ID, denylists and replay detection have nothing to key on.", fix: "Add a random jti and store revoked IDs with TTL = exp.", category: "Claims" });
  else checks.push({ id: "jti", severity: "pass", title: "JWT ID present — revocable", detail: "Token can be individually revoked or replay-tracked.", fix: "No action needed.", category: "Claims" });

  // 10. sensitive claims
  const sensitive = ["password", "secret", "ssn", "credit_card", "private_key"];
  const found = Object.keys(p).filter((k) => sensitive.some((s) => k.toLowerCase().includes(s)));
  if (found.length > 0) checks.push({ id: "pii", severity: "critical", title: `Sensitive data in payload (${found.join(", ")})`, detail: "JWT payloads are only base64 — readable by anyone holding the token.", fix: "Remove secrets from claims; store them server-side keyed by sub.", category: "Privacy" });
  else checks.push({ id: "pii", severity: "pass", title: "No obvious secrets in payload", detail: "No password/secret-like keys detected (heuristic scan).", fix: "Still treat payloads as public — encrypt with JWE if confidentiality is required.", category: "Privacy" });

  // 11. roles / scope
  const hasRoles = p.roles != null || p.permissions != null || p.scope != null;
  if (!hasRoles) checks.push({ id: "scope", severity: "info", title: "No roles / scope claims", detail: "Authorization must be looked up elsewhere on every request.", fix: "Embed minimal scope/roles for stateless authz; keep them coarse-grained.", category: "AuthZ" });
  else {
    const roles = Array.isArray(p.roles) ? p.roles : [];
    if (roles.includes("superuser") || roles.includes("admin"))
      checks.push({ id: "scope", severity: "warning", title: "Privileged role embedded in token", detail: `roles=[${roles.join(", ")}] — theft of this token equals full compromise.`, fix: "Shorten TTL for privileged tokens; require step-up MFA for admin actions.", category: "AuthZ" });
    else checks.push({ id: "scope", severity: "pass", title: "Least-privilege scopes present", detail: "Token carries standard user-level authorization.", fix: "No action needed.", category: "AuthZ" });
  }

  // 12. size
  const size = new TextEncoder().encode(token.trim()).length;
  if (size > 4096) checks.push({ id: "size", severity: "warning", title: `Oversized token (${(size / 1024).toFixed(1)} KB)`, detail: "Large tokens bloat every request and risk exceeding 4–8 KB header/cookie limits.", fix: "Trim claims; move extended profile data behind a /me endpoint.", category: "Transport" });
  else checks.push({ id: "size", severity: "pass", title: `Compact size (${size} bytes)`, detail: "Fits comfortably in headers and cookies.", fix: "No action needed.", category: "Transport" });

  // score
  let score = 100;
  checks.forEach((c) => {
    if (c.severity === "critical") score -= 25;
    else if (c.severity === "warning") score -= 10;
    else if (c.severity === "info") score -= 2;
  });
  score = Math.max(0, Math.min(100, score));
  return { checks, score };
}

const SEV = {
  critical: { icon: ShieldX, cls: "border-rose-500/30 bg-rose-500/[0.07]", badge: "bg-rose-500/15 text-rose-300 border-rose-500/30", label: "Critical" },
  warning: { icon: ShieldAlert, cls: "border-amber-500/30 bg-amber-500/[0.06]", badge: "bg-amber-500/15 text-amber-300 border-amber-500/30", label: "Warning" },
  pass: { icon: ShieldCheck, cls: "border-emerald-500/20 bg-emerald-500/[0.04]", badge: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30", label: "Pass" },
  info: { icon: Info, cls: "border-indigo-500/25 bg-indigo-500/[0.05]", badge: "bg-indigo-500/15 text-indigo-300 border-indigo-500/30", label: "Info" },
};

export default function SecurityChecker({ token, issuer }: { token: string; issuer: string }) {
  const { checks, score } = useMemo(() => runChecks(token, issuer), [token, issuer]);

  const counts = {
    critical: checks.filter((c) => c.severity === "critical").length,
    warning: checks.filter((c) => c.severity === "warning").length,
    pass: checks.filter((c) => c.severity === "pass").length,
    info: checks.filter((c) => c.severity === "info").length,
  };

  const grade = score >= 90 ? { l: "A", c: "#10b981" } : score >= 75 ? { l: "B", c: "#84cc16" } : score >= 55 ? { l: "C", c: "#f59e0b" } : score >= 30 ? { l: "D", c: "#fb923c" } : { l: "F", c: "#f43f5e" };
  const ringC = 2 * Math.PI * 40;
  const ringOff = ringC * (1 - score / 100);

  const categories = [...new Set(checks.map((c) => c.category))];

  return (
    <div className="grid gap-4 xl:grid-cols-[300px_1fr]">
      {/* Score card */}
      <div className="card h-fit overflow-hidden">
        <div className="flex items-center gap-2 border-b border-white/[0.06] px-4 py-3">
          <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-indigo-500/15 text-indigo-300">
            <Gauge size={15} />
          </div>
          <div>
            <h3 className="text-[13.5px] font-bold text-white">Token Health Score</h3>
            <p className="font-mono text-[10.5px] text-slate-500">{checks.length} automated checks</p>
          </div>
        </div>
        <div className="flex flex-col items-center px-4 py-5">
          <div className="relative h-[128px] w-[128px]">
            <svg viewBox="0 0 96 96" className="h-full w-full -rotate-90">
              <circle cx="48" cy="48" r="40" fill="none" stroke="rgba(255,255,255,0.07)" strokeWidth="9" />
              <circle cx="48" cy="48" r="40" fill="none" stroke={grade.c} strokeWidth="9" strokeLinecap="round"
                strokeDasharray={ringC} strokeDashoffset={ringOff}
                style={{ transition: "stroke-dashoffset .8s cubic-bezier(.2,.8,.3,1), stroke .3s", filter: `drop-shadow(0 0 8px ${grade.c}66)` }} />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <div className="font-mono text-[30px] font-bold leading-none text-white">{score}</div>
              <div className="mt-1 flex items-center gap-1.5">
                <span className="rounded px-1.5 py-0.5 font-mono text-[11px] font-bold" style={{ background: `${grade.c}22`, color: grade.c }}>
                  Grade {grade.l}
                </span>
              </div>
            </div>
          </div>
          <div className="mt-4 grid w-full grid-cols-4 gap-1.5 text-center">
            <MiniStat n={counts.critical} l="crit" c="text-rose-400" />
            <MiniStat n={counts.warning} l="warn" c="text-amber-400" />
            <MiniStat n={counts.pass} l="pass" c="text-emerald-400" />
            <MiniStat n={counts.info} l="info" c="text-indigo-300" />
          </div>
          <div className="mt-3 w-full rounded-xl border border-white/[0.07] bg-[#070b18] p-2.5 text-[11.5px] leading-relaxed text-slate-400">
            <span className="flex items-center gap-1.5 font-bold text-slate-200"><Lightbulb size={13} className="text-amber-400" /> Top recommendation</span>
            <span className="mt-1 block">
              {checks.find((c) => c.severity === "critical")?.fix ?? checks.find((c) => c.severity === "warning")?.fix ?? "Token posture looks solid. Re-run after every claim change."}
            </span>
          </div>
        </div>
      </div>

      {/* Checklist */}
      <div className="card overflow-hidden">
        <div className="flex flex-wrap items-center gap-2 border-b border-white/[0.06] px-4 py-3">
          <ListChecks size={15} className="text-indigo-400" />
          <h3 className="text-[13.5px] font-bold text-white">Automated Security Checklist</h3>
          <span className="font-mono text-[10.5px] text-slate-500">aud · alg · exp · iss · jti · scope</span>
          <div className="flex-1" />
          <span className="hidden items-center gap-1 font-mono text-[10.5px] text-slate-500 sm:flex"><Globe size={11} /> verified against {issuer}</span>
        </div>
        <div className="max-h-[560px] space-y-4 overflow-y-auto p-4">
          {categories.map((cat) => (
            <div key={cat}>
              <div className="mb-2 flex items-center gap-2">
                <span className="text-[10.5px] font-bold uppercase tracking-widest text-slate-500">{cat}</span>
                <span className="h-px flex-1 bg-white/[0.06]" />
              </div>
              <div className="space-y-2">
                {checks.filter((c) => c.category === cat).map((c) => {
                  const s = SEV[c.severity];
                  const Icon = s.icon;
                  return (
                    <div key={c.id} className={cn("rounded-xl border p-3 transition-colors", s.cls)}>
                      <div className="flex items-start gap-2.5">
                        <Icon size={16} className="mt-0.5 shrink-0" />
                        <div className="min-w-0 flex-1">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="text-[13px] font-bold text-white">{c.title}</span>
                            <span className={cn("rounded border px-1.5 py-0.5 font-mono text-[10px] font-bold", s.badge)}>{s.label}</span>
                          </div>
                          <p className="mt-1 text-[12.5px] leading-relaxed text-slate-400">{c.detail}</p>
                          <p className="mt-1.5 flex items-start gap-1 text-[12px] leading-relaxed text-slate-300">
                            <ChevronRight size={14} className="mt-0.5 shrink-0 text-indigo-400" />
                            <span><b className="text-indigo-300">Fix: </b>{c.fix}</span>
                          </p>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
        <div className="flex items-center gap-2 border-t border-white/[0.06] bg-[#070b18]/60 px-4 py-2.5 font-mono text-[10.5px] text-slate-500">
          <KeyRound size={12} /> heuristic audit — always confirm with server-side verification
          <span className="mx-1">·</span>
          <Clock size={12} /> live · recomputed on every keystroke
        </div>
      </div>
    </div>
  );
}

function MiniStat({ n, l, c }: { n: number; l: string; c: string }) {
  return (
    <div className="rounded-lg border border-white/[0.07] bg-[#070b18] py-1.5">
      <div className={cn("font-mono text-[16px] font-bold", c)}>{n}</div>
      <div className="text-[9px] font-bold uppercase tracking-widest text-slate-500">{l}</div>
    </div>
  );
}
