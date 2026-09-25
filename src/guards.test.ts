import { describe, expect, it } from "vitest";
import { AGENT_ID_RE, isSafeRepoPath } from "./guards.js";

describe("isSafeRepoPath", () => {
  it("accepts ordinary repo-relative paths", () => {
    expect(isSafeRepoPath("README.md")).toBe(true);
    expect(isSafeRepoPath("web/src/App.tsx")).toBe(true);
    expect(isSafeRepoPath(".github/workflows/deploy.yml")).toBe(true);
  });

  it("rejects dot-segments that fetch() would normalize out of the owned repo", () => {
    expect(isSafeRepoPath("../../other-agent/contents/x")).toBe(false);
    expect(isSafeRepoPath("web/../../../x")).toBe(false);
    expect(isSafeRepoPath("./x")).toBe(false);
    expect(isSafeRepoPath("%2e%2e/x")).toBe(false);
    expect(isSafeRepoPath("a%2Fb")).toBe(false);
  });

  it("rejects empty, absolute, and query/fragment-bearing paths", () => {
    expect(isSafeRepoPath("")).toBe(false);
    expect(isSafeRepoPath("/etc/passwd")).toBe(false);
    expect(isSafeRepoPath("a//b")).toBe(false);
    expect(isSafeRepoPath("a?ref=other")).toBe(false);
    expect(isSafeRepoPath("a#b")).toBe(false);
    expect(isSafeRepoPath("a\\b")).toBe(false);
  });
});

describe("AGENT_ID_RE", () => {
  it("allows slugs and rejects anything that could reshape a GitHub API path", () => {
    expect(AGENT_ID_RE.test("my-agent-2")).toBe(true);
    expect(AGENT_ID_RE.test("../platform")).toBe(false);
    expect(AGENT_ID_RE.test("a/b")).toBe(false);
    expect(AGENT_ID_RE.test("")).toBe(false);
  });
});
