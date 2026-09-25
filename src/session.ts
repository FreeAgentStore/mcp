// FAGS session token verification — must match the FAGS host's createSession()
// (FreeAgentStore/platform workers/host/src/api.ts): HMAC-SHA256 over
// base64(JSON payload), signature hex-encoded.
// Token format: base64(payload) + "." + hex(hmac).

export interface SessionPayload {
  uid: string;
  login?: string;
  avatar?: string;
  roles?: string[];
  appRoles?: Record<string, string[]>;
  iat?: number;
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
  const expected = await hmacHex(body, signingKey);
  if (!timingSafeEqual(sig, expected)) return null;
  let payload: SessionPayload;
  try {
    payload = JSON.parse(atob(body)) as SessionPayload;
  } catch {
    return null;
  }
  if (typeof payload.exp !== 'number' || payload.exp < Math.floor(Date.now() / 1000)) return null;
  return payload;
}

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

function timingSafeEqual(a: string, b: string): boolean {
  const maxLen = Math.max(a.length, b.length);
  let diff = a.length ^ b.length;
  for (let i = 0; i < maxLen; i++) diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return diff === 0;
}
