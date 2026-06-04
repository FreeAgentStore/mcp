// FAS session token verification — vendored from fas/platform/packages/backend/src/lib/session.ts.
// Tokens are HMAC-SHA256 signed: base64url(payload) + "." + base64url(hmac).

export interface SessionPayload {
  uid: string;
  roles?: string[];
  appRoles?: Record<string, string[]>;
  iat: number;
  exp: number;
}

export async function verifySession(
  token: string,
  signingKey: string,
): Promise<SessionPayload | null> {
  const dot = token.lastIndexOf('.');
  if (dot < 0) return null;
  const body = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  const expected = await hmac(body, signingKey);
  if (!timingSafeEqual(sig, expected)) return null;
  let payload: SessionPayload;
  try {
    payload = JSON.parse(b64urlDecode(body)) as SessionPayload;
  } catch {
    return null;
  }
  if (payload.exp < Math.floor(Date.now() / 1000)) return null;
  return payload;
}

async function hmac(data: string, keyMaterial: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(keyMaterial),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  return b64urlBytes(new Uint8Array(sig));
}

function b64urlBytes(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlDecode(s: string): string {
  const padded = s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4);
  return atob(padded);
}

function timingSafeEqual(a: string, b: string): boolean {
  const maxLen = Math.max(a.length, b.length);
  let diff = a.length ^ b.length;
  for (let i = 0; i < maxLen; i++) diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return diff === 0;
}
