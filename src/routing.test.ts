import { describe, expect, it, vi } from "vitest";
import { type AuthSink, dispatchMcp, landing } from "./routing.js";

const ORIGIN = "https://mcp.freeagentstore.online";
const TOKEN = "eyJ1aWQiOiJ1c2VyLTEyMyJ9.deadbeef";

async function expectJsonRpc405(res: Response) {
  expect(res.status).toBe(405);
  expect(res.headers.get("location")).toBeNull();
  expect(res.headers.get("content-type")).toBe("application/json");
  expect(res.headers.get("allow")).toBe("GET, HEAD");
  const body = (await res.json()) as {
    jsonrpc: string;
    id: unknown;
    error: { code: number; message: string };
  };
  expect(body.jsonrpc).toBe("2.0");
  expect(body.id).toBeNull();
  expect(Number.isInteger(body.error.code)).toBe(true);
  expect(body.error.message).toContain(`${ORIGIN}/mcp`);
}

describe("landing path /", () => {
  it("answers a JSON-RPC POST with a JSON-RPC 405, not 200/HTML/redirect", async () => {
    const res = landing(
      new Request(`${ORIGIN}/`, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json, text/event-stream" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }),
      }),
    );
    await expectJsonRpc405(res);
  });

  it("answers a legacy-SSE GET (Accept: text/event-stream) with the JSON-RPC 405", async () => {
    const res = landing(new Request(`${ORIGIN}/`, { headers: { accept: "text/event-stream" } }));
    await expectJsonRpc405(res);
  });

  it("still serves the plain-text page to a browser GET", async () => {
    const res = landing(new Request(`${ORIGIN}/`, { headers: { accept: "text/html" } }));
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("text/plain");
    expect(await res.text()).toContain("/mcp");
  });

  it("leaves HEAD and OPTIONS alone so CORS preflight is unaffected", () => {
    expect(landing(new Request(`${ORIGIN}/`, { method: "HEAD" })).status).toBe(200);
    expect(landing(new Request(`${ORIGIN}/`, { method: "OPTIONS" })).status).toBe(200);
  });
});

// ── /mcp dispatch: the session token must never be put on the URL ──

function makeNamespace() {
  const setAuth = vi.fn<AuthSink["setAuth"]>(async () => {});
  const idFromName = vi.fn((name: string) => ({ name }));
  const namespace = {
    idFromName,
    get: vi.fn(() => ({ setAuth })),
  } as unknown as DurableObjectNamespace;
  return { namespace, setAuth, idFromName };
}

function mcpRequest(sessionId?: string) {
  const headers: Record<string, string> = {
    authorization: `Bearer ${TOKEN}`,
    "content-type": "application/json",
  };
  if (sessionId) headers["mcp-session-id"] = sessionId;
  return new Request(`${ORIGIN}/mcp`, {
    method: "POST",
    headers,
    body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }),
  });
}

describe("/mcp dispatch", () => {
  it("does not put the session token or user id in the dispatched URL", async () => {
    const { namespace } = makeNamespace();
    const serve = vi.fn(async (_req: Request) => new Response("ok"));
    await dispatchMcp(mcpRequest("sess-1"), namespace, { userId: "user-123", token: TOKEN }, serve);

    expect(serve).toHaveBeenCalledTimes(1);
    const dispatched = new URL(serve.mock.calls[0][0].url);
    expect(dispatched.search).toBe("");
    expect(dispatched.searchParams.has("token")).toBe(false);
    expect(dispatched.searchParams.has("userId")).toBe(false);
    expect(dispatched.toString()).not.toContain(TOKEN);
    expect(dispatched.toString()).not.toContain("user-123");
  });

  it("hands auth to the session Durable Object over RPC, addressed as serve() names it", async () => {
    const { namespace, setAuth, idFromName } = makeNamespace();
    const serve = vi.fn(async () => new Response("ok"));
    await dispatchMcp(mcpRequest("sess-1"), namespace, { userId: "user-123", token: TOKEN }, serve);

    expect(idFromName).toHaveBeenCalledWith("streamable-http:sess-1");
    expect(setAuth).toHaveBeenCalledWith({ userId: "user-123", token: TOKEN });
  });

  it("skips setAuth for unauthenticated callers and for the pre-session initialize request", async () => {
    const { namespace, setAuth } = makeNamespace();
    const serve = vi.fn(async () => new Response("ok"));
    await dispatchMcp(mcpRequest("sess-1"), namespace, {}, serve);
    await dispatchMcp(mcpRequest(), namespace, { userId: "user-123", token: TOKEN }, serve);
    expect(setAuth).not.toHaveBeenCalled();
    expect(serve).toHaveBeenCalledTimes(2);
  });

  it("still dispatches when the session DO rejects setAuth", async () => {
    const { namespace, setAuth } = makeNamespace();
    setAuth.mockRejectedValueOnce(new Error("DO unavailable"));
    const serve = vi.fn(async () => new Response("ok"));
    const res = await dispatchMcp(mcpRequest("sess-1"), namespace, { userId: "u", token: TOKEN }, serve);
    expect(res.status).toBe(200);
  });
});
