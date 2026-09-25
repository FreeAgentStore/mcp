import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  type AuditEvent,
  audit,
  dryRun,
  errText,
  isReadOnly,
  listAuditEvents,
  requireConfirmation,
  requireWritable,
  type SafetyContext,
  txt,
} from './safety.js';

// ── Test doubles ───────────────────────────────────────────────

/** In-memory KV standing in for the Workers KV binding (TTL recorded, not enforced). */
function makeKV() {
  const store = new Map<string, string>();
  const ttls = new Map<string, number | undefined>();
  const kv = {
    async get(key: string): Promise<string | null> {
      const v = store.get(key);
      return v === undefined ? null : v;
    },
    async put(key: string, value: string, opts?: { expirationTtl?: number }): Promise<void> {
      store.set(key, value);
      ttls.set(key, opts?.expirationTtl);
    },
    async delete(key: string): Promise<void> {
      store.delete(key);
    },
    async list(opts?: { prefix?: string; limit?: number }) {
      const prefix = opts?.prefix ?? '';
      // Real KV returns keys in lexicographic (ascending) order.
      const keys = [...store.keys()]
        .filter((k) => k.startsWith(prefix))
        .sort()
        .slice(0, opts?.limit ?? 1000)
        .map((name) => ({ name }));
      return { keys, list_complete: true, cacheStatus: null };
    },
    _store: store,
    _ttls: ttls,
  };
  return kv as unknown as KVNamespace & {
    _store: Map<string, string>;
    _ttls: Map<string, number | undefined>;
  };
}

const SUBJECT = 'user-123';

function ctxWith(env: SafetyContext['env'], subject: string = SUBJECT): SafetyContext {
  return { env, subject };
}

/** A context with no subject at all — an unauthenticated caller. */
function anonCtx(env: SafetyContext['env']): SafetyContext {
  return { env };
}

// ── Response helpers ───────────────────────────────────────────

describe('txt', () => {
  it('returns a single text content block without isError', () => {
    expect(txt('hello')).toEqual({ content: [{ type: 'text', text: 'hello' }] });
    expect(txt('hello')).not.toHaveProperty('isError');
  });
});

describe('errText', () => {
  it('returns a single text content block with isError: true', () => {
    expect(errText('nope')).toEqual({
      content: [{ type: 'text', text: 'nope' }],
      isError: true,
    });
  });
});

describe('dryRun', () => {
  it('returns a non-error preview naming the tool and echoing the input', () => {
    const res = dryRun('delete_agent', { agent_id: 'demo', archive_repo: true });
    expect(res.isError).toBeUndefined();
    expect(res.content).toHaveLength(1);
    expect(res.content[0].text).toMatch(/^\[DRY RUN\] delete_agent would execute with:/);
    expect(res.content[0].text).toContain('"agent_id": "demo"');
    expect(res.content[0].text).toContain('"archive_repo": true');
  });
});

// ── Read-only mode ─────────────────────────────────────────────

describe('isReadOnly', () => {
  it.each([
    ['1', true],
    ['true', true],
    ['TRUE', true],
    ['0', false],
    ['false', false],
    ['', false],
    ['yes', false],
    [undefined, false],
  ])('MCP_READ_ONLY=%j → %s', (value, expected) => {
    expect(isReadOnly(ctxWith({ MCP_READ_ONLY: value }))).toBe(expected);
  });
});

describe('requireWritable', () => {
  it('returns null when the server is writable', () => {
    expect(requireWritable(ctxWith({}))).toBeNull();
    expect(requireWritable(ctxWith({ MCP_READ_ONLY: '0' }))).toBeNull();
  });

  it('returns an isError result when the server is read-only', () => {
    const res = requireWritable(ctxWith({ MCP_READ_ONLY: '1' }));
    expect(res).not.toBeNull();
    expect(res?.isError).toBe(true);
    expect(res?.content[0].text).toMatch(/read-only mode/);
  });
});

// ── Confirmation gate ──────────────────────────────────────────

describe('requireConfirmation', () => {
  const ctx = ctxWith({});

  it('returns null when confirm matches the expected token exactly', () => {
    expect(requireConfirmation(ctx, 'delete_agent', 'demo', 'demo')).toBeNull();
  });

  it('returns an isError prompt naming the expected token when confirm is missing', () => {
    const res = requireConfirmation(ctx, 'delete_agent', undefined, 'demo');
    expect(res?.isError).toBe(true);
    expect(res?.content[0].text).toContain('delete_agent is destructive');
    expect(res?.content[0].text).toContain('confirm="demo"');
  });

  it('returns an isError prompt when confirm is wrong', () => {
    const res = requireConfirmation(ctx, 'delete_file', 'other', 'web/src/tools.ts');
    expect(res?.isError).toBe(true);
    expect(res?.content[0].text).toContain('confirm="web/src/tools.ts"');
  });

  it('is case-sensitive', () => {
    expect(requireConfirmation(ctx, 'delete_agent', 'Demo', 'demo')).not.toBeNull();
  });
});

// ── Audit log ──────────────────────────────────────────────────

describe('audit', () => {
  beforeEach(() => {
    vi.useRealTimers();
  });

  it('no-ops without throwing when OAUTH_KV is unbound', async () => {
    await expect(
      audit(ctxWith({}), { tool: 'update_files', action: 'success' }),
    ).resolves.toBeUndefined();
  });

  it('no-ops for anonymous callers (no subject) even when KV is bound', async () => {
    const kv = makeKV();
    await audit(anonCtx({ OAUTH_KV: kv }), { tool: 'update_files', action: 'success' });
    await audit(ctxWith({ OAUTH_KV: kv }, ''), { tool: 'update_files', action: 'success' });
    expect(kv._store.size).toBe(0);
  });

  it('writes one key per event, prefixed by the subject, with a 90-day TTL', async () => {
    const kv = makeKV();
    const ctx = ctxWith({ OAUTH_KV: kv });
    await audit(ctx, { tool: 'update_files', action: 'success', result: 'abc123' });
    await audit(ctx, { tool: 'delete_file', action: 'blocked' });

    expect(kv._store.size).toBe(2);
    for (const key of kv._store.keys()) {
      expect(key.startsWith(`audit:${SUBJECT}:`)).toBe(true);
      expect(kv._ttls.get(key)).toBe(90 * 86_400);
    }
  });

  it('stores a JSON body carrying the event fields, the subject, and an ISO timestamp', async () => {
    const kv = makeKV();
    const before = Date.now();
    await audit(ctxWith({ OAUTH_KV: kv }), {
      tool: 'create_agent',
      action: 'dry_run',
      input: { agent_id: 'demo', name: 'Demo' },
    });
    const [raw] = [...kv._store.values()];
    const body = JSON.parse(raw) as AuditEvent;
    expect(body.subject).toBe(SUBJECT);
    expect(body.tool).toBe('create_agent');
    expect(body.action).toBe('dry_run');
    expect(body.input).toEqual({ agent_id: 'demo', name: 'Demo' });
    expect(typeof body.ts).toBe('string');
    const parsed = Date.parse(body.ts);
    expect(parsed).toBeGreaterThanOrEqual(before - 1000);
    expect(parsed).toBeLessThanOrEqual(Date.now() + 1000);
  });

  it('redacts credential-shaped keys and truncates long strings before writing', async () => {
    const kv = makeKV();
    await audit(ctxWith({ OAUTH_KV: kv }), {
      tool: 'update_files',
      action: 'success',
      input: {
        agent_id: 'demo',
        token: 'sk-live-secret',
        nested: { api_key: 'AIza-secret', authorization: 'Bearer x' },
        blob: 'x'.repeat(600),
      },
    });
    const body = JSON.parse([...kv._store.values()][0]) as AuditEvent;
    const input = body.input as Record<string, unknown>;
    expect(input.agent_id).toBe('demo');
    expect(input.token).toBe('[redacted]');
    expect((input.nested as Record<string, unknown>).api_key).toBe('[redacted]');
    expect((input.nested as Record<string, unknown>).authorization).toBe('[redacted]');
    expect((input.blob as string).length).toBe(503);
    expect(input.blob as string).toMatch(/\.\.\.$/);
    expect(JSON.stringify(body)).not.toContain('secret');
  });
});

describe('listAuditEvents', () => {
  it('returns [] when OAUTH_KV is unbound', async () => {
    expect(await listAuditEvents(ctxWith({}))).toEqual([]);
  });

  it('returns [] for anonymous callers', async () => {
    const kv = makeKV();
    await audit(ctxWith({ OAUTH_KV: kv }), { tool: 'update_files', action: 'success' });
    expect(await listAuditEvents(anonCtx({ OAUTH_KV: kv }))).toEqual([]);
  });

  it('returns parsed events for the subject only, newest first', async () => {
    vi.useFakeTimers();
    try {
      const kv = makeKV();
      const mine = ctxWith({ OAUTH_KV: kv });
      const theirs = ctxWith({ OAUTH_KV: kv }, 'user-999');

      vi.setSystemTime(new Date('2026-09-01T00:00:00Z'));
      await audit(mine, { tool: 'create_agent', action: 'success' });
      vi.setSystemTime(new Date('2026-09-02T00:00:00Z'));
      await audit(theirs, { tool: 'delete_agent', action: 'success' });
      vi.setSystemTime(new Date('2026-09-03T00:00:00Z'));
      await audit(mine, { tool: 'update_files', action: 'failed' });

      const events = await listAuditEvents(mine);
      expect(events.map((e) => e.tool)).toEqual(['update_files', 'create_agent']);
      expect(events.every((e) => e.subject === SUBJECT)).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it('honours limit, returning the newest events rather than the oldest', async () => {
    vi.useFakeTimers();
    try {
      const kv = makeKV();
      const ctx = ctxWith({ OAUTH_KV: kv });
      for (let day = 1; day <= 5; day++) {
        vi.setSystemTime(new Date(`2026-09-0${day}T00:00:00Z`));
        await audit(ctx, { tool: `tool-${day}`, action: 'success' });
      }
      const events = await listAuditEvents(ctx, 2);
      expect(events.map((e) => e.tool)).toEqual(['tool-5', 'tool-4']);
    } finally {
      vi.useRealTimers();
    }
  });

  it('skips entries whose stored value is not valid JSON', async () => {
    const kv = makeKV();
    const ctx = ctxWith({ OAUTH_KV: kv });
    await audit(ctx, { tool: 'update_files', action: 'success' });
    kv._store.set(`audit:${SUBJECT}:2026-09-09T00:00:00.000Z:corrupt`, '{not json');
    const events = await listAuditEvents(ctx);
    expect(events).toHaveLength(1);
    expect(events[0].tool).toBe('update_files');
  });
});
