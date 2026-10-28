export interface DecodedJwt {
  raw: string;
  headerB64: string;
  payloadB64: string;
  signatureB64: string;
  header: Record<string, any> | null;
  payload: Record<string, any> | null;
  headerError: string | null;
  payloadError: string | null;
  isValidStructure: boolean;
  parts: number;
}

export function base64UrlEncode(input: string): string {
  const b64 = btoa(unescape(encodeURIComponent(input)));
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64UrlDecodeToString(b64url: string): string {
  let b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4;
  if (pad === 2) b64 += "==";
  else if (pad === 3) b64 += "=";
  else if (pad === 1) throw new Error("Invalid base64url length");
  const binary = atob(b64);
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

export function parseJwt(token: string): DecodedJwt {
  const raw = token.trim();
  const empty: DecodedJwt = {
    raw,
    headerB64: "",
    payloadB64: "",
    signatureB64: "",
    header: null,
    payload: null,
    headerError: null,
    payloadError: null,
    isValidStructure: false,
    parts: 0,
  };
  if (!raw) return empty;
  // strip Bearer prefix
  const cleaned = raw.replace(/^Bearer\s+/i, "").trim().replace(/\s+/g, "");
  const parts = cleaned.split(".");
  empty.parts = parts.length;
  if (parts.length !== 3) return { ...empty, raw: cleaned };
  const [h, p, s] = parts;
  empty.headerB64 = h;
  empty.payloadB64 = p;
  empty.signatureB64 = s;
  try {
    empty.header = JSON.parse(base64UrlDecodeToString(h));
  } catch {
    empty.headerError = "Header is not valid base64url JSON";
  }
  try {
    empty.payload = JSON.parse(base64UrlDecodeToString(p));
  } catch {
    empty.payloadError = "Payload is not valid base64url JSON";
  }
  empty.isValidStructure = !empty.headerError && !empty.payloadError && !!empty.header && !!empty.payload;
  empty.raw = cleaned;
  return empty;
}

export function formatUnix(ts: number | undefined | null): string {
  if (typeof ts !== "number" || !Number.isFinite(ts)) return "—";
  try {
    const d = new Date(ts * 1000);
    return d.toLocaleString("en-US", {
      month: "short",
      day: "numeric",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    });
  } catch {
    return "—";
  }
}

export function formatUnixUTC(ts: number | undefined | null): string {
  if (typeof ts !== "number" || !Number.isFinite(ts)) return "—";
  try {
    return new Date(ts * 1000).toISOString().replace("T", " ").replace("Z", " UTC");
  } catch {
    return "—";
  }
}

export function getTokenStatus(payload: Record<string, any> | null): {
  state: "valid" | "expired" | "not-yet" | "expiring" | "unknown" | "no-exp";
  remainingSec: number | null;
  totalLifespanSec: number | null;
  percentElapsed: number | null;
} {
  if (!payload) return { state: "unknown", remainingSec: null, totalLifespanSec: null, percentElapsed: null };
  const now = Math.floor(Date.now() / 1000);
  const exp = typeof payload.exp === "number" ? payload.exp : null;
  const iat = typeof payload.iat === "number" ? payload.iat : null;
  const nbf = typeof payload.nbf === "number" ? payload.nbf : null;
  if (nbf && now < nbf)
    return { state: "not-yet", remainingSec: nbf - now, totalLifespanSec: null, percentElapsed: null };
  if (exp === null)
    return { state: "no-exp", remainingSec: null, totalLifespanSec: null, percentElapsed: null };
  const remaining = exp - now;
  const total = iat ? exp - iat : null;
  const elapsed = total ? Math.min(1, Math.max(0, 1 - remaining / total)) : null;
  if (remaining <= 0) return { state: "expired", remainingSec: remaining, totalLifespanSec: total, percentElapsed: elapsed };
  if (remaining < 300) return { state: "expiring", remainingSec: remaining, totalLifespanSec: total, percentElapsed: elapsed };
  return { state: "valid", remainingSec: remaining, totalLifespanSec: total, percentElapsed: elapsed };
}

export function formatDuration(totalSeconds: number): string {
  const abs = Math.abs(Math.floor(totalSeconds));
  const d = Math.floor(abs / 86400);
  const h = Math.floor((abs % 86400) / 3600);
  const m = Math.floor((abs % 3600) / 60);
  const s = abs % 60;
  if (d > 0) return `${d}d ${h}h ${m}m ${s}s`;
  if (h > 0) return `${h}h ${m}m ${s}s`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

export function breakdownDuration(totalSeconds: number) {
  const abs = Math.max(0, Math.floor(totalSeconds));
  return {
    days: Math.floor(abs / 86400),
    hours: Math.floor((abs % 86400) / 3600),
    minutes: Math.floor((abs % 3600) / 60),
    seconds: abs % 60,
  };
}

export function byteSize(str: string): number {
  return new TextEncoder().encode(str).length;
}

/* ---------- HMAC-SHA256 verification via WebCrypto ---------- */

function b64UrlToBytes(b64url: string): Uint8Array {
  let b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4;
  if (pad === 2) b64 += "==";
  else if (pad === 3) b64 += "=";
  const binary = atob(b64);
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

function bytesToB64Url(bytes: Uint8Array): string {
  let binary = "";
  bytes.forEach((b) => (binary += String.fromCharCode(b)));
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export async function hmacSign(unsignedToken: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(unsignedToken));
  return bytesToB64Url(new Uint8Array(sig));
}

export async function verifyHS256(token: string, secret: string): Promise<{ ok: boolean; expected: string; reason: string }> {
  try {
    const cleaned = token.trim().replace(/^Bearer\s+/i, "").trim();
    const parts = cleaned.split(".");
    if (parts.length !== 3) return { ok: false, expected: "", reason: "Malformed token structure" };
    const unsigned = `${parts[0]}.${parts[1]}`;
    const expected = await hmacSign(unsigned, secret);
    const a = b64UrlToBytes(parts[2]);
    const b = b64UrlToBytes(expected);
    if (a.length !== b.length) return { ok: false, expected, reason: "Signature length mismatch" };
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0
      ? { ok: true, expected, reason: "HMAC-SHA256 signature matches provided secret" }
      : { ok: false, expected, reason: "Signature does not match this secret" };
  } catch (e: any) {
    return { ok: false, expected: "", reason: e?.message ?? "Verification failed" };
  }
}

export function randomBase64Url(bytes: number): string {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return bytesToB64Url(arr);
}
