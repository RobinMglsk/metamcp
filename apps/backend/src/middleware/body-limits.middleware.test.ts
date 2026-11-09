import type { AddressInfo } from "node:net";

import express from "express";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

const logger = vi.hoisted(() => ({
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  debug: vi.fn(),
}));
vi.mock("@/utils/logger", () => ({ default: logger }));

import {
  createJsonBodyParser,
  resolveTrpcLimit,
} from "./body-limits.middleware";

const hasValidSession = vi.fn();
let server: ReturnType<express.Express["listen"]>;
let base: string;

beforeAll(async () => {
  const app = express();
  app.use(
    createJsonBodyParser({
      hasValidSession,
      trpcLimitBytes: 1024 * 1024, // 1 MB keeps the test fast
    }),
  );
  const echo: express.RequestHandler = (req, res) => {
    res.json({ bytes: JSON.stringify(req.body ?? null).length });
  };
  app.post("/trpc/x", echo);
  app.get("/trpc/x", (_req, res) => {
    res.json({ ok: true });
  });
  app.options("/trpc/x", (_req, res) => {
    res.sendStatus(204);
  });
  app.post("/MCP-PROXY/x", async (req, res) => {
    let n = 0;
    for await (const c of req) n += (c as Buffer).length;
    res.json({ raw: n, parsed: req.body !== undefined });
  });
  app.post("/api/auth/x", echo);
  app.post("/metamcp/ep/api/tool", async (req, res) => {
    // not parsed by the global middleware: raw stream stays available
    let n = 0;
    for await (const c of req) n += (c as Buffer).length;
    res.json({ raw: n, parsed: req.body !== undefined });
  });
  await new Promise<void>((resolve) => {
    server = app.listen(0, "127.0.0.1", () => resolve());
  });
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

const post = (path: string, bytes: number) =>
  fetch(base + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ data: "x".repeat(bytes) }),
  });

describe("JSON body limits", () => {
  it("accepts small bodies everywhere without checking a session", async () => {
    hasValidSession.mockClear();
    expect((await post("/trpc/x", 1000)).status).toBe(200);
    expect((await post("/api/auth/x", 1000)).status).toBe(200);
    expect(hasValidSession).not.toHaveBeenCalled();
  });

  it("rejects bodies over 100 KB on non-tRPC routes, even for signed-in users", async () => {
    hasValidSession.mockResolvedValue(true);
    expect((await post("/api/auth/x", 200 * 1024)).status).toBe(413);
  });

  it("requires a session for large tRPC bodies", async () => {
    hasValidSession.mockResolvedValue(false);
    const denied = await post("/trpc/x", 200 * 1024);
    expect(denied.status).toBe(401);
    expect(hasValidSession).toHaveBeenCalled();

    hasValidSession.mockResolvedValue(true);
    expect((await post("/trpc/x", 200 * 1024)).status).toBe(200);
  });

  it("still enforces the larger tRPC limit for signed-in users", async () => {
    hasValidSession.mockResolvedValue(true);
    expect((await post("/trpc/x", 2 * 1024 * 1024)).status).toBe(413);
  });

  it("fails closed when the session check throws", async () => {
    hasValidSession.mockRejectedValue(new Error("db down"));
    expect((await post("/trpc/x", 200 * 1024)).status).toBe(500);
  });

  it("leaves proxy/public-endpoint routes unparsed", async () => {
    const r = await post("/metamcp/ep/api/tool", 500 * 1024);
    expect(r.status).toBe(200);
    const j = (await r.json()) as { parsed: boolean; raw: number };
    expect(j.parsed).toBe(false);
    expect(j.raw).toBeGreaterThan(500 * 1024);
  });
});

describe("requests without a body", () => {
  it("public tRPC queries and CORS preflights need no session", async () => {
    hasValidSession.mockClear();
    hasValidSession.mockResolvedValue(false);
    const get = await fetch(base + "/trpc/x");
    expect(get.status).toBe(200);
    const options = await fetch(base + "/trpc/x", { method: "OPTIONS" });
    expect(options.status).toBe(204);
    expect(hasValidSession).not.toHaveBeenCalled();
  });
});

describe("path matching", () => {
  it("is case-insensitive like Express routing", async () => {
    // /MCP-PROXY/ must keep its raw stream (not parsed by the 100 KB parser)
    const r = await post("/MCP-PROXY/x", 500 * 1024);
    expect(r.status).toBe(200);
    expect(((await r.json()) as { parsed: boolean }).parsed).toBe(false);
  });

  it("applies the tRPC rules to /TRPC/ too", async () => {
    hasValidSession.mockResolvedValue(false);
    expect((await post("/TRPC/x", 200 * 1024)).status).toBe(401);
  });
});

describe("failures", () => {
  it("logs a failing session check", async () => {
    logger.error.mockClear();
    hasValidSession.mockRejectedValue(new Error("db down"));
    expect((await post("/trpc/x", 200 * 1024)).status).toBe(500);
    expect(logger.error).toHaveBeenCalled();
  });
});

describe("resolveTrpcLimit", () => {
  it("defaults when unset or empty", () => {
    expect(resolveTrpcLimit(undefined)).toBe(10 * 1024 * 1024);
    expect(resolveTrpcLimit("  ")).toBe(10 * 1024 * 1024);
  });

  it("accepts integers of at least 100 KB", () => {
    expect(resolveTrpcLimit("2097152")).toBe(2097152);
    expect(resolveTrpcLimit("102400")).toBe(102400);
  });

  it("ignores values that would be stricter than the small limit or invalid", () => {
    for (const bad of ["1024", "-5", "0", "abc", "1.5", "NaN"]) {
      expect(resolveTrpcLimit(bad)).toBe(10 * 1024 * 1024);
    }
    expect(logger.warn).toHaveBeenCalled();
  });
});
