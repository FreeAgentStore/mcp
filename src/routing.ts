/** Transport-level routing helpers for the worker entry — kept out of index.ts
 *  so they can be tested without loading the agents/McpAgent runtime. */

export interface McpAuth {
  userId?: string;
  token?: string;
}

/** The Durable Object RPC surface the MCP entry uses to hand auth to a session. */
export interface AuthSink {
  setAuth(props: McpAuth): Promise<void>;
}

/**
 * Is this an MCP protocol client rather than a person in a browser?
 *
 * A client pointed at the origin instead of `/mcp` asks for the event stream
 * with `GET / Accept: text/event-stream` (the legacy SSE transport), or POSTs
 * JSON-RPC. Answering either with 200 and a short non-stream body tells the
 * client "stream opened" and then drops it — and the spec-correct response to a
 * dropped stream is to reconnect, so it redials ~1/sec, forever. The flood is
 * invisible: every response is a 200, nothing throws, no AI tokens are spent,
 * nothing is written to D1, and the MCP rate limiter only counts `tools/call`
 * messages carrying an account, which a bare GET has neither of.
 *
 * OPTIONS and HEAD deliberately return false so CORS preflight is unaffected.
 */
export function isProtocolClient(request: Request): boolean {
  if (request.method === "POST") return true;
  return (request.headers.get("accept") ?? "").includes("text/event-stream");
}

/** The JSON-RPC 405 the MCP spec requires from an endpoint with no stream to offer. */
export function wrongEndpoint(): Response {
  return new Response(
    JSON.stringify({
      jsonrpc: "2.0",
      id: null,
      error: {
        code: -32000,
        message: "Method Not Allowed — the MCP endpoint is https://mcp.freeagentstore.online/mcp",
      },
    }),
    { status: 405, headers: { "content-type": "application/json", allow: "GET, HEAD" } },
  );
}

const LANDING_TEXT = [
  "FreeAgentStore MCP Server",
  "",
  "Connect: npx mcp-remote https://mcp.freeagentstore.online/mcp",
  "",
  "Tools:",
  "  list_agents     — List published agents",
  "  agent_info      — Agent status, URLs, links",
  "  deploy_status   — GitHub Actions deploy history",
  "  create_agent    — Provision new agent (repo + R2 + DNS)",
  "  delete_agent    — Remove agent from store",
  "  write_file      — Commit file to agent repo",
  "  read_file       — Read file from agent repo",
  "  list_files      — Directory listing",
  "  upload_to_r2    — Trigger redeploy",
  "  platform_guide  — Architecture and build guide",
  "  sdk_reference   — SDK API reference",
  "",
  "Auth: OAuth 2.1 (automatic via mcp-remote) or Bearer token.",
].join("\n");

/** GET / — 405 JSON-RPC for protocol clients, plain-text landing page for people. */
export function landing(request: Request): Response {
  if (isProtocolClient(request)) return wrongEndpoint();
  return new Response(LANDING_TEXT, { headers: { "content-type": "text/plain" } });
}

/**
 * Hand the caller's auth to its MCP session, then dispatch the request as-is.
 *
 * Auth goes to the session's Durable Object over the `setAuth` RPC, never onto
 * the URL: `serve()` forwards `request.url` (query string included) to the
 * Durable Object, and query strings end up in access logs, traces and
 * referrers. The session DO is addressed exactly as agents' `serve()` names it
 * (`streamable-http:<Mcp-Session-Id>`). The initialize request has no session
 * id yet, so auth binds from the first request after it.
 */
export async function dispatchMcp(
  request: Request,
  namespace: DurableObjectNamespace,
  auth: McpAuth,
  serve: (request: Request) => Promise<Response>,
): Promise<Response> {
  const sessionId = request.headers.get("mcp-session-id");
  if (auth.token && sessionId) {
    try {
      const stub = namespace.get(namespace.idFromName(`streamable-http:${sessionId}`)) as unknown as AuthSink;
      await stub.setAuth({ userId: auth.userId, token: auth.token });
    } catch {
      // Session DO unreachable — the tools fall back to unauthenticated.
    }
  }
  return serve(request);
}
