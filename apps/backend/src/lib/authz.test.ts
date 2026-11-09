import { beforeEach, describe, expect, it, vi } from "vitest";

const limit = vi.fn();
vi.mock("../db", () => ({
  db: { select: () => ({ from: () => ({ where: () => ({ limit }) }) }) },
}));

import { canMutate, isAdmin } from "./authz";
import { REDACTED, redactSecrets } from "./redact";

beforeEach(() => limit.mockReset());

describe("isAdmin / canMutate", () => {
  it("isAdmin reflects the stored role", async () => {
    limit.mockResolvedValueOnce([{ role: "admin" }]);
    expect(await isAdmin("a")).toBe(true);
    limit.mockResolvedValueOnce([{ role: "user" }]);
    expect(await isAdmin("b")).toBe(false);
    limit.mockResolvedValueOnce([]);
    expect(await isAdmin("missing")).toBe(false);
    expect(await isAdmin(undefined)).toBe(false);
  });

  it("owners may mutate their own resources, others may not", async () => {
    expect(await canMutate("u1", "u1")).toBe(true);
    expect(await canMutate("u1", "u2")).toBe(false);
    expect(limit).not.toHaveBeenCalled();
  });

  it("shared resources (null owner) need admin", async () => {
    limit.mockResolvedValueOnce([{ role: "user" }]);
    expect(await canMutate(null, "u2")).toBe(false);
    limit.mockResolvedValueOnce([{ role: "admin" }]);
    expect(await canMutate(null, "u1")).toBe(true);
  });
});

describe("redactSecrets", () => {
  const server = {
    name: "s",
    env: { API_KEY: "secret" },
    bearerToken: "tok",
    headers: { Authorization: "Bearer x" },
  };

  it("hides credentials of shared servers from non-admins, keeping key names", () => {
    const r = redactSecrets(server, null, { userId: "u2", isAdmin: false });
    expect(r.env).toEqual({ API_KEY: REDACTED });
    expect(r.headers).toEqual({ Authorization: REDACTED });
    expect(r.bearerToken).toBeNull();
    expect(r.name).toBe("s");
  });

  it("shows them to admins and owners", () => {
    expect(redactSecrets(server, null, { userId: "a", isAdmin: true })).toBe(
      server,
    );
    expect(redactSecrets(server, "u1", { userId: "u1", isAdmin: false })).toBe(
      server,
    );
  });
});

describe("redactSecrets: urls and args", () => {
  const base = { env: {}, bearerToken: null, headers: {} };

  it("hides query tokens and userinfo of the url for other users", () => {
    const r = redactSecrets(
      {
        ...base,
        url: "https://user:pw@mcp.example.com/sse?api_key=SECRET&x=1#f",
        args: [],
      },
      null,
      { userId: "u2", isAdmin: false },
    );
    expect(r.url).toBe(`https://mcp.example.com/sse?${REDACTED}#f`);
    expect(r.url).not.toContain("SECRET");
    expect(r.url).not.toContain("pw");
  });

  it("leaves urls without secrets untouched", () => {
    const r = redactSecrets(
      { ...base, url: "https://mcp.example.com/sse", args: [] },
      null,
      {
        userId: "u2",
        isAdmin: false,
      },
    );
    expect(r.url).toBe("https://mcp.example.com/sse");
  });

  it("masks command-line arguments (they often carry tokens) but keeps their count", () => {
    const r = redactSecrets(
      { ...base, url: null, args: ["--token=abc", "-y", "server"] },
      null,
      { userId: "u2", isAdmin: false },
    );
    expect(r.args).toEqual([REDACTED, REDACTED, REDACTED]);
  });

  it("shows everything to admins and owners", () => {
    const server = {
      ...base,
      url: "https://a.example/?k=1",
      args: ["--token=abc"],
    };
    expect(redactSecrets(server, null, { userId: "a", isAdmin: true })).toBe(
      server,
    );
    expect(redactSecrets(server, "u1", { userId: "u1", isAdmin: false })).toBe(
      server,
    );
  });
});
