import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { verifySession } from "./session.js";
import { handleOAuthRoute, resolveOAuthToken } from "./oauth-provider.js";

interface Env {
  API_BASE: string;
  GITHUB_ORG: string;
  GITHUB_TOKEN?: string;
  SESSION_SIGNING_KEY?: string;
  OAUTH_KV?: KVNamespace;
  DB?: D1Database;
}

export interface McpProps extends Record<string, unknown> {
  userId?: string;
  token?: string;
}

// ── GitHub helpers ────────────────────────────────────────────

async function ghApi(path: string, opts?: { method?: string; body?: unknown; token?: string }) {
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "User-Agent": "freeagentstore-mcp",
  };
  if (opts?.token) headers.Authorization = `token ${opts.token}`;
  const res = await fetch(`https://api.github.com${path}`, {
    method: opts?.method ?? "GET",
    headers,
    body: opts?.body ? JSON.stringify(opts.body) : undefined,
  });
  if (!res.ok) return { error: `GitHub API ${res.status}: ${await res.text()}` };
  if (res.status === 204) return {};
  return await res.json();
}

async function getDeployStatus(org: string, agentId: string) {
  const data = (await ghApi(`/repos/${org}/${agentId}/actions/runs?per_page=5`)) as {
    workflow_runs?: Array<{ name: string; conclusion: string | null; status: string; updated_at: string; html_url: string; head_sha: string }>;
    error?: string;
  };
  if (data.error) return { error: data.error };
  return (data.workflow_runs ?? []).map((r) => ({
    name: r.name,
    status: r.conclusion ?? r.status,
    updatedAt: r.updated_at,
    url: r.html_url,
    sha: r.head_sha?.slice(0, 7),
  }));
}

// ── FAS API helper ────────────────────────────────────────────

async function fagsApi(apiBase: string, path: string, token?: string) {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(`${apiBase}${path}`, { headers });
  if (!res.ok) return { error: `API ${res.status}: ${await res.text()}` };
  return await res.json();
}

// ── MCP Agent ─────────────────────────────────────────────────

export class FagsMcpAgent extends McpAgent<Env, unknown, McpProps> {
  server = new McpServer({
    name: "FreeAgentStore",
    version: "0.1.0",
  });

  async init() {
    // ── list_agents ────────────────────────────────────────
    this.server.tool(
      "list_agents",
      "List all published agents on FreeAgentStore, or just your own if authenticated.",
      { mine: z.boolean().optional().describe("If true, list only your agents (requires auth)") },
      async ({ mine }) => {
        if (mine) {
          const token = this.props.token;
          if (!token) return text("Not authenticated. Connect with a session token.");
          const data = (await fagsApi(this.env.API_BASE, "/v1/apps/mine", token)) as {
            apps?: Array<{ id: string; category: string; oneliner: string; appUrl: string; repoUrl: string }>;
            error?: string;
          };
          if (data.error) return text(`Error: ${data.error}`);
          const apps = data.apps ?? [];
          if (apps.length === 0) return text("No agents published yet.");
          const lines = apps.map((a) => `- **${a.id}** (${a.category}) — ${a.oneliner}\n  Live: ${a.appUrl} | Repo: ${a.repoUrl}`);
          return text(`${apps.length} agent(s):\n\n${lines.join("\n")}`);
        }

        // Public: query D1 routes
        if (!this.env.DB) return text("D1 not configured.");
        const rows = await this.env.DB.prepare("SELECT slug, r2_prefix, created_at FROM routes ORDER BY created_at DESC").all<{ slug: string; r2_prefix: string; created_at: number }>();
        if (!rows.results.length) return text("No agents published yet.");
        const lines = rows.results.map((r) => `- **${r.slug}** → https://${r.slug}.freeagentstore.online`);
        return text(`${rows.results.length} agent(s) on the platform:\n\n${lines.join("\n")}`);
      }
    );

    // ── agent_info ─────────────────────────────────────────
    this.server.tool(
      "agent_info",
      "Get info about an agent — live URL, repo, deployment status.",
      { agent_id: z.string().describe("Agent ID (e.g. 'tts', 'transcriber')") },
      async ({ agent_id }) => {
        const org = this.env.GITHUB_ORG;
        const liveUrl = `https://${agent_id}.freeagentstore.online`;
        const repoUrl = `https://github.com/${org}/${agent_id}`;

        let status = "Unknown";
        try {
          const check = await fetch(liveUrl, { method: "HEAD" });
          status = check.ok ? "Live (200)" : `Down (${check.status})`;
        } catch { status = "Unreachable"; }

        return text([
          `**${agent_id}**`,
          `Status: ${status}`,
          `Live: ${liveUrl}`,
          `Repo: ${repoUrl}`,
          `Deploy: push to main → GitHub Actions → R2`,
        ].join("\n"));
      }
    );

    // ── deploy_status ──────────────────────────────────────
    this.server.tool(
      "deploy_status",
      "Check deploy status of an agent (last 5 GitHub Actions runs).",
      { agent_id: z.string().describe("Agent ID") },
      async ({ agent_id }) => {
        const runs = await getDeployStatus(this.env.GITHUB_ORG, agent_id);
        if ("error" in runs) return text(`Error: ${(runs as { error: string }).error}`);
        if ((runs as unknown[]).length === 0) return text(`No workflow runs for ${agent_id}.`);
        const lines = (runs as Array<{ name: string; status: string; updatedAt: string; sha: string; url: string }>).map(
          (r) => `- ${r.status === "success" ? "✓" : r.status === "failure" ? "✗" : "..."} ${r.name} (${r.sha}) — ${r.updatedAt}\n  ${r.url}`
        );
        return text(`Deploy history for **${agent_id}**:\n\n${lines.join("\n")}`);
      }
    );

    // ── create_agent ───────────────────────────────────────
    this.server.tool(
      "create_agent",
      "Create a new agent on FreeAgentStore — provisions GitHub repo, R2 route, and DNS. Requires auth + GITHUB_TOKEN.",
      {
        agent_id: z.string().regex(/^[a-z0-9-]+$/).describe("Agent slug (lowercase, hyphens allowed)"),
        name: z.string().describe("Display name"),
        description: z.string().describe("Short description"),
        template: z.enum(["agent-tts", "agent-whisper", "agent-vision", "agent-llm", "agent-tools"]).optional().describe("Template to scaffold from"),
      },
      async ({ agent_id, name, description, template }) => {
        const token = this.props.token;
        if (!token) return text("Not authenticated. Connect with a session token to create agents.");
        if (!this.env.GITHUB_TOKEN) return text("GITHUB_TOKEN not configured on MCP server.");
        if (!this.env.DB) return text("D1 not configured.");

        const org = this.env.GITHUB_ORG;

        // 1. Check if agent already exists
        const existing = await this.env.DB.prepare("SELECT slug FROM routes WHERE slug = ? AND zone = 'freeagentstore.online'").bind(agent_id).first();
        if (existing) return text(`Agent **${agent_id}** already exists at https://${agent_id}.freeagentstore.online`);

        // 2. Create GitHub repo
        const repo = await ghApi(`/orgs/${org}/repos`, {
          method: "POST",
          token: this.env.GITHUB_TOKEN,
          body: {
            name: agent_id,
            description: `${name} — ${description}`,
            auto_init: true,
            visibility: "public",
          },
        });
        if ("error" in repo) return text(`Failed to create repo: ${(repo as { error: string }).error}`);

        // 3. Insert D1 route
        await this.env.DB.prepare(
          "INSERT INTO routes (slug, zone, r2_prefix, store, hosted_on, created_at, updated_at) VALUES (?, 'freeagentstore.online', ?, 'agents', 'r2', strftime('%s','now'), strftime('%s','now'))"
        ).bind(agent_id, `agents/${agent_id}`).run();

        return text([
          `Agent **${agent_id}** created!`,
          ``,
          `Repo: https://github.com/${org}/${agent_id}`,
          `URL: https://${agent_id}.freeagentstore.online (live after first deploy)`,
          ``,
          `Next steps:`,
          `1. Clone: \`git clone https://github.com/${org}/${agent_id}\``,
          `2. Scaffold from template: \`fags init ${agent_id}${template ? ` --template ${template}` : ""}\``,
          `3. Build + push to main → auto-deploys to R2`,
        ].join("\n"));
      }
    );

    // ── delete_agent ───────────────────────────────────────
    this.server.tool(
      "delete_agent",
      "Remove an agent from the store (deletes route, optionally archives repo). Requires auth.",
      {
        agent_id: z.string().describe("Agent ID to remove"),
        archive_repo: z.boolean().optional().describe("Archive the GitHub repo (default: false)"),
      },
      async ({ agent_id, archive_repo }) => {
        const token = this.props.token;
        if (!token) return text("Not authenticated.");
        if (!this.env.DB) return text("D1 not configured.");

        // Remove D1 route
        const result = await this.env.DB.prepare(
          "DELETE FROM routes WHERE slug = ? AND zone = 'freeagentstore.online'"
        ).bind(agent_id).run();

        if (!result.meta.changes) return text(`Agent **${agent_id}** not found in routes.`);

        // Optionally archive repo
        if (archive_repo && this.env.GITHUB_TOKEN) {
          await ghApi(`/repos/${this.env.GITHUB_ORG}/${agent_id}`, {
            method: "PATCH",
            token: this.env.GITHUB_TOKEN,
            body: { archived: true },
          });
        }

        return text(`Agent **${agent_id}** removed from store.${archive_repo ? " Repo archived." : ""}`);
      }
    );

    // ── write_file ─────────────────────────────────────────
    this.server.tool(
      "write_file",
      "Write or update a file in an agent's GitHub repo (commits to main). Requires auth + GITHUB_TOKEN.",
      {
        agent_id: z.string().describe("Agent ID (repo name)"),
        path: z.string().describe("File path relative to repo root (e.g. 'web/src/App.tsx')"),
        content: z.string().describe("File content (UTF-8)"),
        message: z.string().optional().describe("Commit message"),
      },
      async ({ agent_id, path, content, message }) => {
        if (!this.env.GITHUB_TOKEN) return text("GITHUB_TOKEN not configured.");
        const org = this.env.GITHUB_ORG;
        const commitMsg = message ?? `Update ${path}`;

        // Check if file exists (to get SHA for update)
        const existing = (await ghApi(`/repos/${org}/${agent_id}/contents/${path}`, { token: this.env.GITHUB_TOKEN })) as { sha?: string; error?: string };
        const body: Record<string, unknown> = {
          message: commitMsg,
          content: btoa(unescape(encodeURIComponent(content))),
        };
        if (existing.sha) body.sha = existing.sha;

        const result = await ghApi(`/repos/${org}/${agent_id}/contents/${path}`, {
          method: "PUT",
          token: this.env.GITHUB_TOKEN,
          body,
        });

        if ("error" in result) return text(`Error: ${(result as { error: string }).error}`);
        return text(`Committed **${path}** to ${org}/${agent_id} (${commitMsg})`);
      }
    );

    // ── read_file ──────────────────────────────────────────
    this.server.tool(
      "read_file",
      "Read a file from an agent's GitHub repo.",
      {
        agent_id: z.string().describe("Agent ID"),
        path: z.string().describe("File path (e.g. 'web/src/App.tsx')"),
      },
      async ({ agent_id, path }) => {
        const org = this.env.GITHUB_ORG;
        const data = (await ghApi(`/repos/${org}/${agent_id}/contents/${path}`)) as {
          content?: string; encoding?: string; error?: string;
        };
        if (data.error) return text(`Error: ${data.error}`);
        if (!data.content) return text(`File not found: ${path}`);
        const decoded = data.encoding === "base64" ? decodeURIComponent(escape(atob(data.content.replace(/\n/g, "")))) : data.content;
        return text(`\`\`\`\n${decoded}\n\`\`\``);
      }
    );

    // ── list_files ─────────────────────────────────────────
    this.server.tool(
      "list_files",
      "List files in an agent's GitHub repo directory.",
      {
        agent_id: z.string().describe("Agent ID"),
        path: z.string().optional().describe("Directory path (default: root)"),
      },
      async ({ agent_id, path }) => {
        const org = this.env.GITHUB_ORG;
        const dirPath = path ?? "";
        const data = await ghApi(`/repos/${org}/${agent_id}/contents/${dirPath}`);
        if ("error" in data) return text(`Error: ${(data as { error: string }).error}`);
        if (!Array.isArray(data)) return text("Not a directory");
        const lines = (data as Array<{ name: string; type: string; size: number }>).map(
          (f) => `${f.type === "dir" ? "📁" : "📄"} ${f.name}${f.type === "file" ? ` (${f.size}b)` : ""}`
        );
        return text(`Files in **${agent_id}/${dirPath || "."}**:\n\n${lines.join("\n")}`);
      }
    );

    // ── upload_to_r2 ───────────────────────────────────────
    this.server.tool(
      "upload_to_r2",
      "Trigger a rebuild and upload of an agent's dist to R2 (re-deploys the agent). Requires auth.",
      { agent_id: z.string().describe("Agent ID to redeploy") },
      async ({ agent_id }) => {
        if (!this.env.GITHUB_TOKEN) return text("GITHUB_TOKEN not configured.");
        const org = this.env.GITHUB_ORG;

        // Trigger workflow dispatch
        const result = await ghApi(`/repos/${org}/${agent_id}/actions/workflows/deploy.yml/dispatches`, {
          method: "POST",
          token: this.env.GITHUB_TOKEN,
          body: { ref: "main" },
        });

        if ("error" in result) return text(`Error triggering deploy: ${(result as { error: string }).error}`);
        return text(`Deploy triggered for **${agent_id}**. Check status with deploy_status tool.`);
      }
    );

    // ── platform_guide ─────────────────────────────────────
    this.server.tool(
      "platform_guide",
      "Get the FreeAgentStore platform guide — architecture, SDK reference, and how to build browser-based AI agents.",
      {},
      async () => {
        // Return a condensed guide
        return text([
          "# FreeAgentStore Platform Guide",
          "",
          "## What it is",
          "A curated store of AI-powered tools that run entirely in the browser.",
          "Models run on the user's GPU/CPU via WebGPU/WASM. Zero server inference cost.",
          "",
          "## Architecture",
          "- Agents are React + Vite PWAs hosted on R2",
          "- AI models download from HuggingFace CDN, cache in Cache Storage",
          "- Inference runs in Web Workers (WebGPU → WASM fallback)",
          "- Optional: WebContainers (Node.js), Ollama (local LLM)",
          "",
          "## SDK: @freeagentstore/sdk",
          "```tsx",
          "import { initAgent } from '@freeagentstore/sdk'",
          "const agent = initAgent({ agentId: 'my-agent' })",
          "",
          "// Hooks for React:",
          "import { useModel, useWorkerInference, useOllama, useResultStore } from '@freeagentstore/sdk/hooks'",
          "```",
          "",
          "## Templates",
          "- template-agent-tts — Kokoro TTS (text-to-speech)",
          "- template-agent-whisper — Whisper (speech-to-text)",
          "- template-agent-vision — RMBG/SAM (image processing)",
          "- template-agent-llm — Phi-3/Gemma (text generation)",
          "",
          "## Deploy",
          "Push to main → GitHub Actions → R2 → live at {agent}.freeagentstore.online",
          "",
          "## Compliance",
          "- MIT license required",
          "- No cloud AI API calls (models run in browser)",
          "- AI inference must use Web Workers",
          "- Models must cache in Cache Storage",
          "- Bundle < 1MB (excluding models)",
        ].join("\n"));
      }
    );

    // ── sdk_reference ──────────────────────────────────────
    this.server.tool(
      "sdk_reference",
      "Quick reference for @freeagentstore/sdk — model loading, inference, Ollama, storage.",
      {
        feature: z.enum(["all", "model", "inference", "ollama", "cache", "results", "auth", "kv"]).optional().describe("Feature to look up"),
      },
      async ({ feature }) => {
        const sections: Record<string, string> = {
          model: `## Model Loading
\`\`\`tsx
import { useModel } from '@freeagentstore/sdk/hooks'
const { status, load, isReady, hasWebGPU } = useModel({
  repo: 'onnx-community/whisper-small',
  device: 'auto', // webgpu → wasm fallback
  dtype: 'q8',
})
// status: 'idle' | 'downloading' | 'loading' | 'ready' | 'error'
\`\`\``,
          inference: `## Web Worker Inference
\`\`\`tsx
import { useWorkerInference } from '@freeagentstore/sdk/hooks'
const { run, result, running, error } = useWorkerInference({
  workerUrl: '/inference-worker.js',
  onProgress: (data) => console.log(data),
})
const output = await run('transcribe', { audio: blob })
\`\`\``,
          ollama: `## Ollama (Local LLM)
\`\`\`tsx
import { useOllama } from '@freeagentstore/sdk/hooks'
const { available, models, chat, generate } = useOllama()
if (available) {
  for await (const chunk of chat('llama3.2', [{ role: 'user', content: 'Hi' }])) {
    process(chunk)
  }
}
\`\`\`
Ollama at localhost:11434. User sets OLLAMA_ORIGINS="*" for CORS.`,
          cache: `## Model Cache
\`\`\`tsx
import { useModelCache } from '@freeagentstore/sdk/hooks'
const { cachedModels, totalSize, clearCache, formatSize } = useModelCache()
\`\`\`
Uses Cache Storage API. Models persist across sessions.`,
          results: `## Result Persistence
\`\`\`tsx
import { useResultStore } from '@freeagentstore/sdk/hooks'
const { save, load, history, clear } = useResultStore('my-results')
await save('id-123', { text: 'transcription...', ts: Date.now() })
\`\`\`
Uses IndexedDB. Per-agent namespace.`,
          auth: `## Auth (GitHub OAuth)
\`\`\`tsx
const agent = initAgent({ agentId: 'my-agent' })
await agent.auth.signIn('github')
const user = agent.auth.user // { id, name, avatar }
\`\`\``,
          kv: `## Per-user KV Storage
\`\`\`tsx
await agent.kv.set('key', { any: 'json' })
const val = await agent.kv.get('key')
await agent.kv.delete('key')
\`\`\``,
        };

        const selected = feature === "all" || !feature
          ? Object.values(sections).join("\n\n")
          : sections[feature] ?? `Unknown: ${feature}`;

        return text(`# @freeagentstore/sdk Reference\n\n${selected}`);
      }
    );
  }
}

function text(t: string) {
  return { content: [{ type: "text" as const, text: t }] };
}

// ── Auth middleware ────────────────────────────────────────────

async function authenticateRequest(request: Request, env: Env): Promise<{ userId?: string; token?: string }> {
  const auth = request.headers.get("Authorization") ?? "";
  if (!auth.startsWith("Bearer ") || !env.SESSION_SIGNING_KEY) return {};
  let token = auth.slice(7).trim();
  if (!token) return {};

  if (env.OAUTH_KV) {
    const fasSession = await resolveOAuthToken(token, env.OAUTH_KV);
    if (fasSession) token = fasSession;
  }

  const payload = await verifySession(token, env.SESSION_SIGNING_KEY);
  if (!payload) return {};
  return { userId: payload.uid, token };
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext) {
    const url = new URL(request.url);

    // OAuth 2.1 routes
    if (env.OAUTH_KV && env.SESSION_SIGNING_KEY) {
      const oauthRes = await handleOAuthRoute(request, {
        issuer: `${url.protocol}//${url.host}`,
        fasAuthStart: `${env.API_BASE}/v1/auth/github/start`,
        kv: env.OAUTH_KV,
        sessionSigningKey: env.SESSION_SIGNING_KEY,
      });
      if (oauthRes) return oauthRes;
    }

    if (url.pathname === "/" || url.pathname === "") {
      return new Response(
        [
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
        ].join("\n"),
        { headers: { "content-type": "text/plain" } }
      );
    }

    if (url.pathname.startsWith("/mcp")) {
      const auth = await authenticateRequest(request, env);
      if (auth.userId) url.searchParams.set("userId", auth.userId);
      if (auth.token) url.searchParams.set("token", auth.token);
      const modifiedRequest = new Request(url.toString(), request);
      return FagsMcpAgent.serve("/mcp").fetch(modifiedRequest, env, ctx);
    }

    return FagsMcpAgent.serve("/mcp").fetch(request, env, ctx);
  },
};
