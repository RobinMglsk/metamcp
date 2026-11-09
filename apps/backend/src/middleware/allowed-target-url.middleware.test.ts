import { beforeEach, describe, expect, it, vi } from "vitest";

const { policyFor } = vi.hoisted(() => ({ policyFor: vi.fn() }));
vi.mock("../lib/authz", () => ({ outboundPolicyForUser: policyFor }));
vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), error: vi.fn(), warn: vi.fn(), debug: vi.fn() },
}));

import { createAllowedTargetUrlMiddleware } from "./allowed-target-url.middleware";

const run = async (query: Record<string, unknown>, user = { id: "u1" }) => {
  const res = {
    status: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
  };
  const next = vi.fn();
  await createAllowedTargetUrlMiddleware()(
    { query, user } as never,
    res as never,
    next,
  );
  return { res, next };
};

const NON_ADMIN = { allowPrivate: false };
const ADMIN = { allowPrivate: true };

beforeEach(() => policyFor.mockReset());

describe("inspector proxy target URL check", () => {
  it("refuses a non-admin's loopback / private target with a generic 403", async () => {
    policyFor.mockResolvedValue(NON_ADMIN);
    for (const url of [
      "http://127.0.0.1:8080/",
      "http://10.0.0.5/sse",
      "http://[::1]/",
    ]) {
      const { res, next } = await run({ transportType: "SSE", url });
      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith({
        error: "Forbidden",
        message: "The URL is not allowed",
      });
      expect(next).not.toHaveBeenCalled();
    }
  });

  it("refuses metadata targets even for an administrator", async () => {
    policyFor.mockResolvedValue(ADMIN);
    const { res, next } = await run({
      transportType: "STREAMABLE_HTTP",
      url: "http://169.254.169.254/latest/meta-data/",
    });
    expect(res.status).toHaveBeenCalledWith(403);
    expect(next).not.toHaveBeenCalled();
  });

  it("lets an administrator reach an internal server", async () => {
    policyFor.mockResolvedValue(ADMIN);
    const { res, next } = await run({
      transportType: "SSE",
      url: "http://127.0.0.1:9000/sse",
    });
    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
  });

  it("ignores requests that are not HTTP-based proxy connections", async () => {
    const stdio = await run({ transportType: "STDIO", command: "x" });
    const noUrl = await run({ transportType: "SSE" });
    expect(stdio.next).toHaveBeenCalled();
    expect(noUrl.next).toHaveBeenCalled();
    expect(policyFor).not.toHaveBeenCalled();
  });

  it("asks for the authenticated user's policy", async () => {
    policyFor.mockResolvedValue(NON_ADMIN);
    await run(
      { transportType: "SSE", url: "https://mcp.example.com/sse" },
      { id: "user-9" },
    ).catch(() => undefined);
    expect(policyFor).toHaveBeenCalledWith("user-9");
  });

  it("fails closed with a 500 when something unexpected breaks", async () => {
    const req = {
      query: { transportType: "SSE", url: "https://x.example/sse" },
      get user(): never {
        throw new Error("boom");
      },
    };
    const res = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn().mockReturnThis(),
    };
    const next = vi.fn();
    await createAllowedTargetUrlMiddleware()(req as never, res as never, next);
    expect(res.status).toHaveBeenCalledWith(500);
    expect(next).not.toHaveBeenCalled();
  });
});
