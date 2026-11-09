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
