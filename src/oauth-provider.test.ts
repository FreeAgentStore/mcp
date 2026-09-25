import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  DEFAULT_FAGS_AUTH_START,
  handleOAuthRoute,
  type OAuthConfig,
  oauthConfigFromEnv,
  resolveOAuthToken,
} from './oauth-provider.js';

// ── Test doubles ───────────────────────────────────────────────

/** In-memory KV standing in for the Workers KV binding (TTL ignored). */
function makeKV() {
  const store = new Map<string, string>();
  const kv = {
    async get(key: string): Promise<string | null> {
      const v = store.get(key);
      return v === undefined ? null : v;
    },
    async put(key: string, value: string): Promise<void> {
      store.set(key, value);
    },
    async delete(key: string): Promise<void> {
      store.delete(key);
    },
    _store: store,
  };
  return kv as unknown as KVNamespace & { _store: Map<string, string> };
}

const ISSUER = 'https://mcp.test';
const FAGS_AUTH_START = 'https://freeagentstore.online/v1/auth/github/start';
const SIGNING_KEY = 'test-signing-key';
const REDIRECT_URI = 'https://client.example/callback';

function makeConfig(kv: KVNamespace): OAuthConfig {
  return { issuer: ISSUER, fagsAuthStart: FAGS_AUTH_START, kv, sessionSigningKey: SIGNING_KEY };
}

// ── Session signing (mirrors src/session.ts: base64(payload) + "." + hex(hmac)) ──

async function hmacHex(data: string, keyMaterial: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(keyMaterial),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  return Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/** Produce a validly-signed FAGS session token in the host's format. */
async function signSession(key = SIGNING_KEY): Promise<string> {
  const payload = {
    uid: 'user-123',
    login: 'test-user',
    exp: Math.floor(Date.now() / 1000) + 3600,
  };
  const body = btoa(JSON.stringify(payload));
  const sig = await hmacHex(body, key);
  return `${body}.${sig}`;
}

/**
 * Stub the server-to-server exchange the callback performs. When `session` is a
 * string, FAGS responds 200 {fags_session}; when null, it refuses (400) so
 * exchangeLoginCode() returns null. Cleared by afterEach.
 */
function stubExchange(session: string | null) {
  const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
      session === null
        ? new Response(JSON.stringify({ error: 'invalid or expired code' }), { status: 400 })
        : new Response(JSON.stringify({ fags_session: session }), { status: 200 }),
  );
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}

/** Run /oauth/callback with the given login code and (optional) nonce cookie. */
async function doCallback(config: OAuthConfig, code: string | null, nonce: string | null) {
  const url = new URL(`${ISSUER}/oauth/callback`);
  if (code !== null) url.searchParams.set('code', code);
  const headers: Record<string, string> = nonce ? { Cookie: `__mcp_nonce=${nonce}` } : {};
  const res = await handleOAuthRoute(new Request(url.toString(), { headers }), config);
  return res!;
}

/** POST /oauth/token with the given fields. */
async function doToken(config: OAuthConfig, fields: Record<string, string>) {
  const res = await handleOAuthRoute(
    new Request(`${ISSUER}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(fields).toString(),
    }),
    config,
  );
  return res!;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

// ── PKCE helper ────────────────────────────────────────────────

async function makePkce() {
  const verifier = 'abcdef0123456789-abcdef0123456789-verifier';
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  const b64url = (bytes: Uint8Array) => {
    let bin = '';
    for (const b of bytes) bin += String.fromCharCode(b);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };
  const challenge = b64url(new Uint8Array(digest));
  return { verifier, challenge };
}

// ── Flow helpers ───────────────────────────────────────────────

async function registerClient(config: OAuthConfig): Promise<string> {
  const res = await handleOAuthRoute(
    new Request(`${ISSUER}/oauth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ redirect_uris: [REDIRECT_URI], client_name: 'test-client' }),
    }),
    config,
  );
  const body = (await res!.json()) as { client_id: string };
  return body.client_id;
}

function nonceFromSetCookie(setCookie: string | null): string | null {
  if (!setCookie) return null;
  const m = /__mcp_nonce=([^;]*)/.exec(setCookie);
  return m ? m[1] : null;
}

/** Run /oauth/authorize; return the response plus the nonce it set. */
async function doAuthorize(
  config: OAuthConfig,
  clientId: string,
  challenge: string,
  state?: string,
) {
  const url = new URL(`${ISSUER}/oauth/authorize`);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', clientId);
  url.searchParams.set('redirect_uri', REDIRECT_URI);
  url.searchParams.set('code_challenge', challenge);
  url.searchParams.set('code_challenge_method', 'S256');
  if (state) url.searchParams.set('state', state);
  const res = await handleOAuthRoute(new Request(url.toString()), config);
  const nonce = nonceFromSetCookie(res!.headers.get('set-cookie'));
  return { res: res!, nonce };
}

// ── Tests ──────────────────────────────────────────────────────

describe('oauth-provider', () => {
  it('serves authorization-server metadata pointing at /oauth/* endpoints', async () => {
    const config = makeConfig(makeKV());
    const res = await handleOAuthRoute(
      new Request(`${ISSUER}/.well-known/oauth-authorization-server`),
      config,
    );
    expect(res).not.toBeNull();
    const meta = (await res!.json()) as Record<string, unknown>;
    expect(meta.issuer).toBe(ISSUER);
    expect(meta.authorization_endpoint).toBe(`${ISSUER}/oauth/authorize`);
    expect(meta.token_endpoint).toBe(`${ISSUER}/oauth/token`);
    expect(meta.registration_endpoint).toBe(`${ISSUER}/oauth/register`);
    expect(meta.code_challenge_methods_supported).toEqual(['S256']);
  });

  it('registers a dynamic client and returns a client_id', async () => {
    const config = makeConfig(makeKV());
    const res = await handleOAuthRoute(
      new Request(`${ISSUER}/oauth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ redirect_uris: [REDIRECT_URI] }),
      }),
      config,
    );
    expect(res!.status).toBe(201);
    const body = (await res!.json()) as { client_id: string; redirect_uris: string[] };
    expect(typeof body.client_id).toBe('string');
    expect(body.client_id.length).toBeGreaterThan(0);
    expect(body.redirect_uris).toEqual([REDIRECT_URI]);
  });

  it('authorize sets an HttpOnly __mcp_nonce cookie and redirects to FAGS auth', async () => {
    const config = makeConfig(makeKV());
    const clientId = await registerClient(config);
    const { challenge } = await makePkce();
    const { res, nonce } = await doAuthorize(config, clientId, challenge);

    expect(res.status).toBe(302);
    const location = res.headers.get('location') ?? '';
    expect(location.startsWith(FAGS_AUTH_START)).toBe(true);

    const setCookie = res.headers.get('set-cookie') ?? '';
    expect(setCookie).toContain('__mcp_nonce=');
    expect(setCookie).toContain('HttpOnly');
    expect(setCookie).toContain('SameSite=Lax');
    expect(nonce).toBeTruthy();

    // The nonce must NOT be leaked into the redirect URL.
    expect(location).not.toContain(nonce as string);
    expect(location).not.toContain('nonce=');
  });

  it('callback with no nonce cookie returns 400 "missing nonce cookie or code"', async () => {
    const config = makeConfig(makeKV());
    const url = new URL(`${ISSUER}/oauth/callback`);
    url.searchParams.set('code', 'anything');
    const res = await handleOAuthRoute(new Request(url.toString()), config);
    expect(res!.status).toBe(400);
    expect(await res!.text()).toBe('missing nonce cookie or code');
  });

  it('callback with a mismatched/expired nonce returns 400', async () => {
    const config = makeConfig(makeKV());
    const url = new URL(`${ISSUER}/oauth/callback`);
    url.searchParams.set('code', 'one-time-code');
    const res = await handleOAuthRoute(
      new Request(url.toString(), { headers: { Cookie: '__mcp_nonce=does-not-exist' } }),
      config,
    );
    expect(res!.status).toBe(400);
    expect(await res!.text()).toBe('invalid or expired nonce');
  });

  it('callback rejects a code the backend refuses (exchange fails)', async () => {
    const config = makeConfig(makeKV());
    const clientId = await registerClient(config);
    const { challenge } = await makePkce();
    const { nonce } = await doAuthorize(config, clientId, challenge);

    stubExchange(null); // FAGS says the code is invalid/expired
    const url = new URL(`${ISSUER}/oauth/callback`);
    url.searchParams.set('code', 'bad-or-used-code');
    const res = await handleOAuthRoute(
      new Request(url.toString(), { headers: { Cookie: `__mcp_nonce=${nonce}` } }),
      config,
    );
    expect(res!.status).toBe(400);
    expect(await res!.text()).toBe('invalid or expired code');
  });

  it('callback with valid nonce + code exchanges server-to-server and issues an auth code', async () => {
    const config = makeConfig(makeKV());
    const clientId = await registerClient(config);
    const { challenge } = await makePkce();
    const { nonce } = await doAuthorize(config, clientId, challenge, 'client-state-xyz');

    stubExchange(await signSession());
    const url = new URL(`${ISSUER}/oauth/callback`);
    url.searchParams.set('code', 'one-time-login-code');
    const res = await handleOAuthRoute(
      new Request(url.toString(), { headers: { Cookie: `__mcp_nonce=${nonce}` } }),
      config,
    );

    expect(res!.status).toBe(302);
    const location = new URL(res!.headers.get('location') ?? '');
    expect(`${location.origin}${location.pathname}`).toBe(REDIRECT_URI);
    expect(location.searchParams.get('code')).toBeTruthy();
    expect(location.searchParams.get('state')).toBe('client-state-xyz');

    // Nonce cookie is cleared on the way out.
    expect(res!.headers.get('set-cookie') ?? '').toContain('Max-Age=0');
  });

  it('token exchange with a bad code returns 400 invalid_grant', async () => {
    const config = makeConfig(makeKV());
    const { verifier } = await makePkce();
    const res = await handleOAuthRoute(
      new Request(`${ISSUER}/oauth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: 'nonexistent-code',
          redirect_uri: REDIRECT_URI,
          client_id: 'some-client',
          code_verifier: verifier,
        }).toString(),
      }),
      config,
    );
    expect(res!.status).toBe(400);
    expect((await res!.json()) as { error: string }).toMatchObject({ error: 'invalid_grant' });
  });

  it('full flow: register → authorize → callback → token yields an access_token', async () => {
    const config = makeConfig(makeKV());
    const clientId = await registerClient(config);
    const { verifier, challenge } = await makePkce();

    // authorize
    const { nonce } = await doAuthorize(config, clientId, challenge);

    // callback → auth code (session redeemed via server-to-server exchange)
    stubExchange(await signSession());
    const cbUrl = new URL(`${ISSUER}/oauth/callback`);
    cbUrl.searchParams.set('code', 'one-time-login-code');
    const cbRes = await handleOAuthRoute(
      new Request(cbUrl.toString(), { headers: { Cookie: `__mcp_nonce=${nonce}` } }),
      config,
    );
    const code = new URL(cbRes!.headers.get('location') ?? '').searchParams.get('code')!;
    expect(code).toBeTruthy();

    // token exchange
    const tokRes = await handleOAuthRoute(
      new Request(`${ISSUER}/oauth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri: REDIRECT_URI,
          client_id: clientId,
          code_verifier: verifier,
        }).toString(),
      }),
      config,
    );
    expect(tokRes!.status).toBe(200);
    const token = (await tokRes!.json()) as { access_token: string; token_type: string };
    expect(token.token_type).toBe('bearer');
    expect(typeof token.access_token).toBe('string');

    // the opaque token resolves back to the underlying FAGS session
    const session = await resolveOAuthToken(token.access_token, config.kv);
    expect(session).not.toBeNull();
  });

  it('never leaks a session token in any redirect it generates', async () => {
    const config = makeConfig(makeKV());
    const clientId = await registerClient(config);
    const { challenge } = await makePkce();

    const { res: authRes, nonce } = await doAuthorize(config, clientId, challenge);
    expect(authRes.headers.get('location') ?? '').not.toContain('fas_session');
    expect(authRes.headers.get('location') ?? '').not.toContain('fags_session');
    expect(authRes.headers.get('location') ?? '').not.toContain('session_code');
    expect(authRes.headers.get('set-cookie') ?? '').not.toContain('fags_session');

    const signed = await signSession();
    stubExchange(signed);
    const cbUrl = new URL(`${ISSUER}/oauth/callback`);
    cbUrl.searchParams.set('code', 'one-time-login-code');
    const cbRes = await handleOAuthRoute(
      new Request(cbUrl.toString(), { headers: { Cookie: `__mcp_nonce=${nonce}` } }),
      config,
    );
    const cbLocation = cbRes!.headers.get('location') ?? '';
    expect(cbLocation).not.toContain('fags_session');
    expect(cbLocation).not.toContain('session_code');
    expect(cbLocation).not.toContain(signed);
  });
  it('authorize sends the browser to /v1/auth/github/start with return_to = our /oauth/callback', async () => {
    const config = makeConfig(makeKV());
    const clientId = await registerClient(config);
    const { challenge } = await makePkce();
    const { res } = await doAuthorize(config, clientId, challenge);
    const location = new URL(res.headers.get('location') ?? '');
    expect(`${location.origin}${location.pathname}`).toBe(FAGS_AUTH_START);
    expect(location.searchParams.get('return_to')).toBe(`${ISSUER}/oauth/callback`);
    expect(res.headers.get('set-cookie') ?? '').toContain('Secure');
  });

  it('authorize rejects an unregistered redirect_uri without setting a cookie', async () => {
    const config = makeConfig(makeKV());
    const clientId = await registerClient(config);
    const url = new URL(`${ISSUER}/oauth/authorize`);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('client_id', clientId);
    url.searchParams.set('redirect_uri', 'https://evil.example/cb');
    url.searchParams.set('code_challenge', 'x');
    const res = await handleOAuthRoute(new Request(url.toString()), config);
    expect(res!.status).toBe(400);
    expect(res!.headers.get('set-cookie')).toBeNull();
  });

  it('callback with a nonce cookie but no code returns 400 and clears the cookie', async () => {
    const config = makeConfig(makeKV());
    const clientId = await registerClient(config);
    const { challenge } = await makePkce();
    const { nonce } = await doAuthorize(config, clientId, challenge);
    const res = await doCallback(config, null, nonce);
    expect(res.status).toBe(400);
    expect(await res.text()).toBe('missing nonce cookie or code');
    expect(res.headers.get('set-cookie') ?? '').toContain('Max-Age=0');
  });

  it('ignores a nonce passed in the URL instead of the cookie (old FAS-shaped callback)', async () => {
    const config = makeConfig(makeKV());
    const clientId = await registerClient(config);
    const { challenge } = await makePkce();
    const { nonce } = await doAuthorize(config, clientId, challenge);
    const signed = await signSession();
    const fetchMock = stubExchange(signed);
    const url = new URL(`${ISSUER}/oauth/callback`);
    url.searchParams.set('nonce', nonce as string);
    url.searchParams.set('fas_session', signed);
    const res = await handleOAuthRoute(new Request(url.toString()), config);
    expect(res!.status).toBe(400);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('redeems the login code server-to-server: POST to the FAGS origin, code in the body only', async () => {
    const config = makeConfig(makeKV());
    const clientId = await registerClient(config);
    const { challenge } = await makePkce();
    const { nonce } = await doAuthorize(config, clientId, challenge);
    const fetchMock = stubExchange(await signSession());
    await doCallback(config, 'login-code-123', nonce);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [input, init] = fetchMock.mock.calls[0];
    expect(String(input)).toBe('https://freeagentstore.online/v1/auth/mcp/exchange');
    expect(String(input)).not.toContain('login-code-123');
    expect(init?.method).toBe('POST');
    expect(JSON.parse(String(init?.body))).toEqual({ code: 'login-code-123' });
  });

  it('the nonce is single-use: replaying the callback fails', async () => {
    const config = makeConfig(makeKV());
    const clientId = await registerClient(config);
    const { challenge } = await makePkce();
    const { nonce } = await doAuthorize(config, clientId, challenge);
    stubExchange(await signSession());
    expect((await doCallback(config, 'code-1', nonce)).status).toBe(302);
    const replay = await doCallback(config, 'code-2', nonce);
    expect(replay.status).toBe(400);
    expect(await replay.text()).toBe('invalid or expired nonce');
  });

  it('callback rejects a session the backend returns with a bad signature', async () => {
    const config = makeConfig(makeKV());
    const clientId = await registerClient(config);
    const { challenge } = await makePkce();
    const { nonce } = await doAuthorize(config, clientId, challenge);
    stubExchange(await signSession('some-other-key'));
    const res = await doCallback(config, 'login-code', nonce);
    expect(res.status).toBe(400);
    expect(await res.text()).toBe('invalid session');
    expect(res.headers.get('location')).toBeNull();
  });

  it('token exchange fails PKCE with the wrong verifier, and the code is then spent', async () => {
    const config = makeConfig(makeKV());
    const clientId = await registerClient(config);
    const { verifier, challenge } = await makePkce();
    const { nonce } = await doAuthorize(config, clientId, challenge);
    stubExchange(await signSession());
    const cb = await doCallback(config, 'login-code', nonce);
    const code = new URL(cb.headers.get('location') ?? '').searchParams.get('code')!;

    const base = { grant_type: 'authorization_code', code, redirect_uri: REDIRECT_URI, client_id: clientId };
    const bad = await doToken(config, { ...base, code_verifier: 'wrong-verifier' });
    expect(bad.status).toBe(400);
    expect(((await bad.json()) as { error: string }).error).toBe('invalid_grant');

    const retry = await doToken(config, { ...base, code_verifier: verifier });
    expect(retry.status).toBe(400);
  });

  it('token exchange rejects a mismatched client_id', async () => {
    const config = makeConfig(makeKV());
    const clientId = await registerClient(config);
    const { verifier, challenge } = await makePkce();
    const { nonce } = await doAuthorize(config, clientId, challenge);
    stubExchange(await signSession());
    const cb = await doCallback(config, 'login-code', nonce);
    const code = new URL(cb.headers.get('location') ?? '').searchParams.get('code')!;
    const res = await doToken(config, {
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      client_id: 'someone-else',
      code_verifier: verifier,
    });
    expect(res.status).toBe(400);
  });
});

describe('disabled providers', () => {
  const kv = makeKV();

  it('OAuth is disabled when OAUTH_KV is unbound', () => {
    expect(oauthConfigFromEnv({ SESSION_SIGNING_KEY: 'k' }, ISSUER)).toBeNull();
  });

  it('OAuth is disabled when SESSION_SIGNING_KEY is unset or empty', () => {
    expect(oauthConfigFromEnv({ OAUTH_KV: kv }, ISSUER)).toBeNull();
    expect(oauthConfigFromEnv({ OAUTH_KV: kv, SESSION_SIGNING_KEY: '' }, ISSUER)).toBeNull();
  });

  it('defaults the auth start to the FAGS one-time-code entry point, not a FAS URL', () => {
    const config = oauthConfigFromEnv({ OAUTH_KV: kv, SESSION_SIGNING_KEY: 'k' }, ISSUER)!;
    expect(config.fagsAuthStart).toBe(DEFAULT_FAGS_AUTH_START);
    expect(DEFAULT_FAGS_AUTH_START).toBe('https://freeagentstore.online/v1/auth/github/start');
    expect(config.fagsAuthStart).not.toContain('freeappstore');
  });

  it('honours FAGS_AUTH_START from env', () => {
    const config = oauthConfigFromEnv(
      { OAUTH_KV: kv, SESSION_SIGNING_KEY: 'k', FAGS_AUTH_START: 'https://staging.example/v1/auth/github/start' },
      ISSUER,
    )!;
    expect(config.fagsAuthStart).toBe('https://staging.example/v1/auth/github/start');
  });

  it('callback fails closed when the FAGS exchange endpoint is disabled (503)', async () => {
    const config = makeConfig(makeKV());
    const clientId = await registerClient(config);
    const { challenge } = await makePkce();
    const { nonce } = await doAuthorize(config, clientId, challenge);
    vi.stubGlobal('fetch', vi.fn(async () => new Response('{"error":"OAuth KV not configured"}', { status: 503 })));
    const res = await doCallback(config, 'login-code', nonce);
    expect(res.status).toBe(400);
    expect(res.headers.get('location')).toBeNull();
  });

  it('callback fails closed when the FAGS exchange endpoint is unreachable', async () => {
    const config = makeConfig(makeKV());
    const clientId = await registerClient(config);
    const { challenge } = await makePkce();
    const { nonce } = await doAuthorize(config, clientId, challenge);
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('network down'); }));
    const res = await doCallback(config, 'login-code', nonce);
    expect(res.status).toBe(400);
    expect(res.headers.get('location')).toBeNull();
  });
});

