/**
 * MCP Safety Layer — FAGS platform
 *
 * Vendored from FreeAgentStore/platform workers/mcp/src/safety.ts, which is
 * itself simplified from the FDS/PAGS MCP servers (no scope taxonomy — FAGS
 * gates writes by D1 ownership inside each tool). Provides structured
 * error responses, read-only mode, dry-run, confirmation guards, and a
 * KV-backed audit log for all mutating MCP tools.
 *
 * Keep in sync by hand with the sibling stores — it is vendored, not shared.
 */

// A type alias, not an interface: aliases get an implicit index signature, which
// the MCP SDK's CallToolResult (`[x: string]: unknown`) requires for assignability.
export type TextResult = {
  content: Array<{ type: 'text'; text: string }>;
  isError?: boolean;
};

export interface SafetyContext {
  env: { OAUTH_KV?: KVNamespace; MCP_READ_ONLY?: string };
  /** Authenticated user id — the audit trail is keyed on it. Anonymous callers
   *  (no subject) are not audited, matching FDS/PAGS. */
  subject?: string;
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

/** Success response */
export function txt(text: string): TextResult {
  return { content: [{ type: 'text', text }] };
}

/** Error response — sets isError so MCP clients can distinguish */
export function errText(text: string): TextResult {
  return { content: [{ type: 'text', text }], isError: true };
}

/** Dry-run response */
export function dryRun(tool: string, input: Record<string, unknown>): TextResult {
  return txt(`[DRY RUN] ${tool} would execute with: ${JSON.stringify(input, null, 2)}`);
}

// ---------------------------------------------------------------------------
// Read-only guard
// ---------------------------------------------------------------------------

/** Returns true when MCP_READ_ONLY env var is set to "1" or "true" */
export function isReadOnly(ctx: SafetyContext): boolean {
  const v = ctx.env.MCP_READ_ONLY ?? '';
  return v === '1' || v.toLowerCase() === 'true';
}

/** Returns an errText if the worker is in read-only mode, or null if OK */
export function requireWritable(ctx: SafetyContext): TextResult | null {
  if (isReadOnly(ctx)) {
    return errText('MCP worker is in read-only mode. Mutating operations are disabled.');
  }
  return null;
}

// ---------------------------------------------------------------------------
// Confirmation guard
// ---------------------------------------------------------------------------

/**
 * For destructive operations: the caller must pass `confirm` equal to the
 * resource identifier (agent_id for delete_agent, path for delete_file).
 *
 * Returns an errText if the confirmation token does not match, or null if OK.
 */
export function requireConfirmation(
  _ctx: SafetyContext,
  tool: string,
  confirm: string | undefined,
  expected: string,
): TextResult | null {
  if (confirm !== expected) {
    return errText(`${tool} is destructive. Pass confirm="${expected}" to proceed.`);
  }
  return null;
}

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

const AUDIT_PREFIX = 'audit:';
const AUDIT_TTL_SECONDS = 90 * 86_400;
const MAX_LIST = 200;

export interface AuditEvent {
  ts: string; // ISO-8601
  subject: string;
  tool: string;
  action: 'success' | 'failed' | 'dry_run' | 'blocked';
  input?: Record<string, unknown>;
  result?: string;
}

/**
 * Append an audit event for the subject into OAUTH_KV.
 *
 * One KV key per event (`audit:{subject}:{iso}:{uuid}`) with a 90-day TTL, so
 * concurrent Durable Object instances never race on a shared array and old
 * events expire on their own. No-op for anonymous callers or when OAUTH_KV is
 * unbound, so it is always safe to call.
 */
export async function audit(
  ctx: SafetyContext,
  event: Omit<AuditEvent, 'ts' | 'subject'>,
): Promise<void> {
  if (!ctx.env.OAUTH_KV || !ctx.subject) return;
  const ts = new Date().toISOString();
  const key = `${AUDIT_PREFIX}${ctx.subject}:${ts}:${crypto.randomUUID()}`;
  const record: AuditEvent = { ts, subject: ctx.subject, ...(redact(event) as typeof event) };
  await ctx.env.OAUTH_KV.put(key, JSON.stringify(record), { expirationTtl: AUDIT_TTL_SECONDS });
}

/** Retrieve audit events for the authenticated subject, newest first. */
export async function listAuditEvents(ctx: SafetyContext, limit = 50): Promise<AuditEvent[]> {
  if (!ctx.env.OAUTH_KV || !ctx.subject) return [];
  const safeLimit = Math.max(1, Math.min(MAX_LIST, limit));
  // Keys sort lexicographically, i.e. oldest first. Over-list (KV's per-call
  // cap) and take the newest slice, otherwise `limit` would return the OLDEST
  // events — the bug PAGS hit in its #704.
  const listed = await ctx.env.OAUTH_KV.list({
    prefix: `${AUDIT_PREFIX}${ctx.subject}:`,
    limit: 1000,
  });
  const kv = ctx.env.OAUTH_KV;
  const rows = await Promise.all(
    listed.keys
      .sort((a, b) => b.name.localeCompare(a.name))
      .slice(0, safeLimit)
      .map(async (key) => {
        const raw = await kv.get(key.name);
        if (!raw) return null;
        try {
          return JSON.parse(raw) as AuditEvent;
        } catch {
          return null;
        }
      }),
  );
  return rows.filter((row): row is AuditEvent => row !== null);
}

/** Strip credential-shaped keys and truncate long strings before anything is logged. */
function redact(value: unknown, depth = 0): unknown {
  if (depth > 8) return '[truncated]';
  if (typeof value === 'string') return value.length > 500 ? `${value.slice(0, 500)}...` : value;
  if (Array.isArray(value)) return value.map((item) => redact(item, depth + 1));
  if (!value || typeof value !== 'object') return value;
  const out: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(value)) {
    if (/token|secret|password|credential|authorization|api[_-]?key/i.test(key)) {
      out[key] = '[redacted]';
    } else {
      out[key] = redact(item, depth + 1);
    }
  }
  return out;
}
