import type { AddressInfo } from "node:net";

import express from "express";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import { createJsonBodyParser } from "./body-limits.middleware";

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
