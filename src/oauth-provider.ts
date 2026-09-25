/**
 * OAuth 2.1 provider for FAGS MCP servers — vendorable, self-contained.
 * Vendored from FreeAgentStore/platform workers/mcp/src/oauth-provider.ts.
 * Needs: OAUTH_KV binding, SESSION_SIGNING_KEY, FAGS_AUTH_START var.
 *
 * Browser-bound flow (no session token ever rides in a URL):
 *   1. GET  /oauth/authorize — validate, store the auth request in KV under a
 *      single-use nonce, set a short-lived HttpOnly `__mcp_nonce` cookie, and
 *      redirect to the FAGS GitHub login (/v1/auth/github/start).
 *   2. FAGS authenticates and redirects back to /oauth/callback with a one-time
 *      login code (`?code=`) — an opaque handle, never the session itself.
 *   3. GET  /oauth/callback — read the nonce from the cookie (never the URL),
 *      match it to the stored auth request, redeem the one-time code with FAGS
 *      server-to-server (POST /v1/auth/mcp/exchange) for the session, verify it,
 *      then issue a single-use OAuth authorization code. Clears the cookie.
 *   4. POST /oauth/token — verify PKCE (S256) and mint an opaque access token.
 */

import { verifySession } from "./session.js";

const NONCE_COOKIE = "__mcp_nonce";
/** Auth-request / nonce lifetime and cookie Max-Age (seconds). */
const NONCE_TTL = 600;

/** FAGS login entry point for the MCP one-time-code flow. Not /v1/auth/github:
 *  that flow ends in a browser session cookie and never issues a login code. */
export const DEFAULT_FAGS_AUTH_START = "https://freeagentstore.online/v1/auth/github/start";

export interface OAuthConfig {
  /** Base URL of this MCP server (e.g. "https://mcp.freeagentstore.online") */
  issuer: string;
  /** FAGS auth start URL (e.g. "https://freeagentstore.online/v1/auth/github/start") */
  fagsAuthStart: string;
  /** Workers KV namespace for OAuth state */
  kv: KVNamespace;
  /** HMAC signing key (shared with FAGS backend) for session verification */
  sessionSigningKey: string;
}

/**
 * Build the OAuth config from worker env, or null when the provider is
 * disabled (OAUTH_KV or SESSION_SIGNING_KEY unbound). A disabled provider
 * serves no OAuth routes at all rather than half a flow.
 */
export function oauthConfigFromEnv(
  env: { OAUTH_KV?: KVNamespace; SESSION_SIGNING_KEY?: string; FAGS_AUTH_START?: string },
  issuer: string,
): OAuthConfig | null {
  if (!env.OAUTH_KV || !env.SESSION_SIGNING_KEY) return null;
  return {
    issuer,
    fagsAuthStart: env.FAGS_AUTH_START || DEFAULT_FAGS_AUTH_START,
    kv: env.OAUTH_KV,
    sessionSigningKey: env.SESSION_SIGNING_KEY,
  };
}

const OAUTH_PATHS = new Set([
  "/oauth/register",
  "/oauth/authorize",
  "/oauth/callback",
  "/oauth/token",
]);

/** Try to handle an OAuth-related request. Returns null if not an OAuth path. */
export async function handleOAuthRoute(
  request: Request,
  config: OAuthConfig,
): Promise<Response | null> {
  const url = new URL(request.url);
  const path = url.pathname;

  // CORS preflight for OAuth endpoints
  if (request.method === "OPTIONS") {
    if (path.startsWith("/.well-known/") || OAUTH_PATHS.has(path)) {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
        },
      });
    }
  }

  if (
    path === "/.well-known/oauth-protected-resource" ||
    path === "/.well-known/oauth-protected-resource/mcp"
  ) {
    return json({
      resource: `${config.issuer}/mcp`,
      authorization_servers: [config.issuer],
    });
  }
  if (path === "/.well-known/oauth-authorization-server") {
    return json({
      issuer: config.issuer,
      authorization_endpoint: `${config.issuer}/oauth/authorize`,
      token_endpoint: `${config.issuer}/oauth/token`,
      registration_endpoint: `${config.issuer}/oauth/register`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none"],
    });
  }
  if (path === "/oauth/register" && request.method === "POST") {
    return register(request, config);
  }
  if (path === "/oauth/authorize" && request.method === "GET") {
    return authorize(request, config);
  }
  if (path === "/oauth/callback" && request.method === "GET") {
    return oauthCallback(request, config);
  }
  if (path === "/oauth/token" && request.method === "POST") {
    return tokenExchange(request, config);
  }
  return null;
}

/**
 * Resolve a Bearer token that might be an OAuth access token.
 * Returns the underlying FAGS session string, or null if not found in KV.
 */
export async function resolveOAuthToken(
  bearer: string,
  kv: KVNamespace,
): Promise<string | null> {
  return kv.get(`token:${bearer}`);
}

// ── Internals ──────────────────────────────────────────────

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
    },
  });
}

/** Build a 302 redirect that can also carry Set-Cookie (Response.redirect can't). */
function redirect(location: string, extraHeaders: Record<string, string> = {}): Response {
  return new Response(null, {
    status: 302,
    headers: { Location: location, ...extraHeaders },
  });
}

/** Plain-text 400 that also expires the nonce cookie. */
function reject(message: string): Response {
  return new Response(message, {
    status: 400,
    headers: { "Set-Cookie": clearNonceCookie() },
  });
}

/** Serialize the nonce cookie: HttpOnly + Secure + SameSite=Lax so it survives
 *  the top-level login redirect but is unreadable to scripts and other sites. */
function setNonceCookie(nonce: string): string {
  return `${NONCE_COOKIE}=${nonce}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${NONCE_TTL}`;
}

/** Expire the nonce cookie once the callback has consumed (or rejected) it. */
function clearNonceCookie(): string {
  return `${NONCE_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`;
}

/** Read a single cookie value from the request's Cookie header. */
function readCookie(request: Request, name: string): string | null {
  const header = request.headers.get("Cookie");
  if (!header) return null;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim() || null;
  }
  return null;
}

/** POST /oauth/register — dynamic client registration (required by mcp-remote) */
async function register(request: Request, config: OAuthConfig): Promise<Response> {
  // Rate limit: 20 registrations/hour/IP
  const ip = request.headers.get("CF-Connecting-IP") ?? "unknown";
  const hour = Math.floor(Date.now() / 3_600_000);
  const rlKey = `rl:reg:${ip}:${hour}`;
  const count = parseInt((await config.kv.get(rlKey)) ?? "0", 10);
  if (count >= 20) {
    return json({ error: "rate_limit_exceeded" }, 429);
  }
  await config.kv.put(rlKey, String(count + 1), { expirationTtl: 3600 });

  let body: Record<string, unknown>;
  try {
    body = (await request.json()) as Record<string, unknown>;
  } catch {
    return json({ error: "invalid_request" }, 400);
  }

  const redirectUris = body.redirect_uris;
  if (!Array.isArray(redirectUris) || redirectUris.length === 0) {
    return json({ error: "invalid_redirect_uri" }, 400);
  }

  const clientId = crypto.randomUUID();
  const client = {
    client_id: clientId,
    redirect_uris: redirectUris,
    client_name: body.client_name ?? null,
    grant_types: ["authorization_code"],
    response_types: ["code"],
    token_endpoint_auth_method: "none",
  };
  await config.kv.put(`client:${clientId}`, JSON.stringify(client), {
    expirationTtl: 90 * 86_400, // 90 days
  });

  return json(client, 201);
}

/** GET /oauth/authorize — validate request, store auth state, set nonce cookie, redirect to FAGS login */
async function authorize(request: Request, config: OAuthConfig): Promise<Response> {
  const url = new URL(request.url);
  const responseType = url.searchParams.get("response_type");
  const clientId = url.searchParams.get("client_id");
  const redirectUri = url.searchParams.get("redirect_uri");
  const codeChallenge = url.searchParams.get("code_challenge");
  const codeChallengeMethod = url.searchParams.get("code_challenge_method");
  const state = url.searchParams.get("state");

  if (responseType !== "code") {
    return new Response("unsupported_response_type", { status: 400 });
  }
  if (!clientId || !redirectUri || !codeChallenge) {
    return new Response("missing client_id, redirect_uri, or code_challenge", { status: 400 });
  }
  if (codeChallengeMethod && codeChallengeMethod !== "S256") {
    return new Response("only S256 is supported", { status: 400 });
  }

  // Verify client registration
  const clientRaw = await config.kv.get(`client:${clientId}`);
  if (!clientRaw) {
    return new Response("invalid client_id", { status: 400 });
  }
  const client = JSON.parse(clientRaw) as { redirect_uris: string[] };
  if (!client.redirect_uris.includes(redirectUri)) {
    return new Response("redirect_uri not registered", { status: 400 });
  }

  // Store auth request (single-use nonce, short TTL). The nonce lives in a
  // browser-bound cookie — it is NOT placed in the callback URL.
  const nonce = crypto.randomUUID();
  await config.kv.put(
    `authreq:${nonce}`,
    JSON.stringify({ clientId, redirectUri, codeChallenge, state }),
    { expirationTtl: NONCE_TTL },
  );

  // Redirect to FAGS GitHub login. FAGS returns to /oauth/callback with a
  // one-time login code; the nonce comes back via the cookie, not the URL.
  const fagsUrl = new URL(config.fagsAuthStart);
  fagsUrl.searchParams.set("return_to", new URL("/oauth/callback", config.issuer).toString());

  return redirect(fagsUrl.toString(), { "Set-Cookie": setNonceCookie(nonce) });
}

/** GET /oauth/callback — nonce from cookie + one-time login code from FAGS,
 *  redeemed server-to-server for the session, then issues the OAuth auth code. */
async function oauthCallback(request: Request, config: OAuthConfig): Promise<Response> {
  const url = new URL(request.url);
  const nonce = readCookie(request, NONCE_COOKIE);
  const loginCode = url.searchParams.get("code");

  if (!nonce || !loginCode) {
    return reject("missing nonce cookie or code");
  }

  // Retrieve and consume the auth request bound to this browser's nonce (single-use)
  const reqRaw = await config.kv.get(`authreq:${nonce}`);
  if (!reqRaw) {
    return reject("invalid or expired nonce");
  }
  await config.kv.delete(`authreq:${nonce}`);

  // Redeem the one-time login code for the FAGS session — server-to-server POST,
  // so the session token never rides in a URL. Single-use + short TTL at FAGS.
  const fagsSession = await exchangeLoginCode(config, loginCode);
  if (!fagsSession) {
    return reject("invalid or expired code");
  }

  // Defense in depth: the redeemed session must be a valid, unexpired FAGS session.
  const payload = await verifySession(fagsSession, config.sessionSigningKey);
  if (!payload) {
    return reject("invalid session");
  }

  const authReq = JSON.parse(reqRaw) as {
    clientId: string;
    redirectUri: string;
    codeChallenge: string;
    state: string | null;
  };

  // Generate single-use auth code (short TTL)
  const authCode = crypto.randomUUID();
  await config.kv.put(
    `code:${authCode}`,
    JSON.stringify({
      fagsSession,
      codeChallenge: authReq.codeChallenge,
      redirectUri: authReq.redirectUri,
      clientId: authReq.clientId,
    }),
    { expirationTtl: NONCE_TTL },
  );

  // Redirect to client's redirect_uri with auth code; clear the nonce cookie
  const redirectTo = new URL(authReq.redirectUri);
  redirectTo.searchParams.set("code", authCode);
  if (authReq.state) {
    redirectTo.searchParams.set("state", authReq.state);
  }
  return redirect(redirectTo.toString(), { "Set-Cookie": clearNonceCookie() });
}

/**
 * Redeem a one-time login code with the FAGS backend for the underlying session.
 * POST /v1/auth/mcp/exchange {code} → {fags_session}. The exchange endpoint lives
 * at the FAGS auth origin; derive it from fagsAuthStart. Returns null on any failure.
 */
async function exchangeLoginCode(config: OAuthConfig, code: string): Promise<string | null> {
  const exchangeUrl = new URL("/v1/auth/mcp/exchange", config.fagsAuthStart).toString();
  try {
    const res = await fetch(exchangeUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "freeagentstore-mcp" },
      body: JSON.stringify({ code }),
    });
    if (!res.ok) return null;
    const data = (await res.json()) as { fags_session?: unknown };
    return typeof data.fags_session === "string" && data.fags_session ? data.fags_session : null;
  } catch {
    return null;
  }
}

/** POST /oauth/token — exchange auth code for access token (PKCE S256 verified) */
async function tokenExchange(request: Request, config: OAuthConfig): Promise<Response> {
  let body: URLSearchParams;
  try {
    body = new URLSearchParams(await request.text());
  } catch {
    return json({ error: "invalid_request" }, 400);
  }

  if (body.get("grant_type") !== "authorization_code") {
    return json({ error: "unsupported_grant_type" }, 400);
  }

  const code = body.get("code");
  const redirectUri = body.get("redirect_uri");
  const clientId = body.get("client_id");
  const codeVerifier = body.get("code_verifier");

  if (!code || !redirectUri || !clientId || !codeVerifier) {
    return json({ error: "invalid_request" }, 400);
  }

  // Retrieve and consume auth code (single-use)
  const codeRaw = await config.kv.get(`code:${code}`);
  if (!codeRaw) {
    return json({ error: "invalid_grant" }, 400);
  }
  await config.kv.delete(`code:${code}`);

  const codeData = JSON.parse(codeRaw) as {
    fagsSession: string;
    codeChallenge: string;
    redirectUri: string;
    clientId: string;
  };

  if (codeData.redirectUri !== redirectUri || codeData.clientId !== clientId) {
    return json({ error: "invalid_grant" }, 400);
  }

  // Verify PKCE (S256): SHA-256(code_verifier) must equal code_challenge
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(codeVerifier),
  );
  const computed = btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

  if (computed !== codeData.codeChallenge) {
    return json({ error: "invalid_grant", error_description: "PKCE verification failed" }, 400);
  }

  // Issue opaque access token → maps to FAGS session in KV (24h TTL)
  const accessToken = crypto.randomUUID();
  await config.kv.put(`token:${accessToken}`, codeData.fagsSession, {
    expirationTtl: 86_400,
  });

  return json({
    access_token: accessToken,
    token_type: "bearer",
    expires_in: 86_400,
  });
}
