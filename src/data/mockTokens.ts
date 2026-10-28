import { base64UrlEncode, hmacSign, randomBase64Url } from "../utils/jwt";

export const DEFAULT_SECRET = "authpulse-dev-secret-2026";

export interface TokenFixture {
  id: string;
  name: string;
  description: string;
  tag: string;
  tagColor: "emerald" | "indigo" | "rose";
  alg: string;
  token: string;
  header: Record<string, any>;
  payload: Record<string, any>;
  secretHint: string;
  storageKey: string;
}

function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}

function unsigned(header: object, payload: object): { text: string; h: string; p: string } {
  const h = base64UrlEncode(JSON.stringify(header));
  const p = base64UrlEncode(JSON.stringify(payload));
  return { text: `${h}.${p}`, h, p };
}

function fakeRsaSignature(): string {
  // 256 bytes -> ~342 b64url chars, realistic RS256 signature length
  return randomBase64Url(256);
}

export async function buildMockTokens(): Promise<TokenFixture[]> {
  const now = nowSec();

  // 1 — Standard user session
  const userHeader = { alg: "HS256", typ: "JWT", kid: "dev-key-2026-01" };
  const userPayload = {
    sub: "usr_9f3a2b1c",
    name: "Maya Chen",
    email: "maya.chen@authpulse.dev",
    iss: "https://auth.authpulse.dev",
    aud: "authpulse-api",
    iat: now - 900,
    nbf: now - 900,
    exp: now + 6300,
    jti: "tkn_" + randomBase64Url(12),
    roles: ["user"],
    scope: "openid profile email",
    session_id: "sess_" + randomBase64Url(8),
    mfa_verified: true,
  };
  const userUnsigned = unsigned(userHeader, userPayload);
  const userSig = await hmacSign(userUnsigned.text, DEFAULT_SECRET);

  // 2 — Admin token with extended claims (RS256)
  const adminHeader = { alg: "RS256", typ: "JWT", kid: "prod-rsa-2025-11" };
  const adminPayload = {
    sub: "adm_7c1e9d04",
    name: "Darius Cole",
    email: "darius.cole@authpulse.dev",
    iss: "https://sso.authpulse.io",
    aud: ["authpulse-api", "billing-service", "admin-console"],
    iat: now - 300,
    nbf: now - 300,
    exp: now + 14400,
    jti: "tkn_" + randomBase64Url(12),
    roles: ["admin", "superuser", "billing:read"],
    permissions: ["users:read", "users:write", "tokens:revoke", "audit:read", "billing:read"],
    tenant_id: "tnt_acme_corp",
    org: "Acme Corp",
    mfa_verified: true,
    auth_time: now - 300,
    acr: "urn:authpulse:acr:mfa",
    scope: "openid profile email admin:all",
  };
  const adminUnsigned = unsigned(adminHeader, adminPayload);
  const adminSig = fakeRsaSignature();

  // 3 — Expired token for debugging
  const expiredHeader = { alg: "HS256", typ: "JWT", kid: "dev-key-2025-09" };
  const expiredPayload = {
    sub: "usr_44ab01e9",
    name: "Leo Park",
    email: "leo.park@authpulse.dev",
    iss: "https://auth.authpulse.dev",
    aud: "authpulse-api",
    iat: now - 90000,
    nbf: now - 90000,
    exp: now - 3600,
    jti: "tkn_" + randomBase64Url(12),
    roles: ["user"],
    scope: "openid profile email",
    session_id: "sess_" + randomBase64Url(8),
    mfa_verified: false,
  };
  const expiredUnsigned = unsigned(expiredHeader, expiredPayload);
  const expiredSig = await hmacSign(expiredUnsigned.text, DEFAULT_SECRET);

  return [
    {
      id: "standard-user",
      name: "Standard User Session",
      description: "Typical end-user login with MFA verified, 2h sliding session.",
      tag: "HS256 · Active",
      tagColor: "emerald",
      alg: "HS256",
      token: `${userUnsigned.text}.${userSig}`,
      header: userHeader,
      payload: userPayload,
      secretHint: "Signed with dev secret",
      storageKey: "authpulse:session:user",
    },
    {
      id: "admin-extended",
      name: "Admin · Extended Claims",
      description: "Privileged SSO token with multi-audience, tenant scoping & RBAC permissions.",
      tag: "RS256 · Admin",
      tagColor: "indigo",
      alg: "RS256",
      token: `${adminUnsigned.text}.${adminSig}`,
      header: adminHeader,
      payload: adminPayload,
      secretHint: "Requires JWKS public key",
      storageKey: "authpulse:session:admin",
    },
    {
      id: "expired-debug",
      name: "Expired Token (Debug)",
      description: "Lapsed session for testing refresh & expiry handling. Expired 1h ago.",
      tag: "HS256 · Expired",
      tagColor: "rose",
      alg: "HS256",
      token: `${expiredUnsigned.text}.${expiredSig}`,
      header: expiredHeader,
      payload: expiredPayload,
      secretHint: "Signed with dev secret",
      storageKey: "authpulse:session:expired",
    },
  ];
}

export const ENVIRONMENTS = [
  { id: "development", label: "Development", issuer: "https://auth.authpulse.dev", color: "#10b981" },
  { id: "staging", label: "Staging", issuer: "https://auth.staging.authpulse.dev", color: "#f59e0b" },
  { id: "production", label: "Production SSO", issuer: "https://sso.authpulse.io", color: "#6366f1" },
] as const;

export type EnvId = (typeof ENVIRONMENTS)[number]["id"];
