/** Input guards for tools that build GitHub API URLs from caller input. */

/** Agent slug: lowercase letters, digits, hyphens. Also the repo name. */
export const AGENT_ID_RE = /^[a-z0-9-]+$/;

/**
 * Is `path` safe to append to `/repos/{org}/{agent}/contents/`?
 *
 * fetch() normalizes dot-segments, so `../../other-agent/contents/x` would
 * escape the owned repo and write to another one with the server's token.
 * Reject any `.`/`..` segment (raw or percent-encoded), empty segments,
 * a leading slash, backslashes, and query/fragment characters.
 */
export function isSafeRepoPath(path: string): boolean {
  if (!path || path.length > 1024) return false;
  if (/[\\?#\u0000-\u001f]/.test(path)) return false;
  if (/%2e|%2f|%5c/i.test(path)) return false;
  return path.split("/").every((seg) => seg !== "" && seg !== "." && seg !== "..");
}
