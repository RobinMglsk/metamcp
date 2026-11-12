import express from "express";
import type { AddressInfo } from "net";
import {
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";

const repo = vi.hoisted(() => ({
  createSessionKey: vi.fn(),
  revokeBySessionId: vi.fn(),
}));
vi.mock("../db/repositories/api-keys.repo", () => ({
  ApiKeysRepository: class {
    createSessionKey = repo.createSessionKey;
    revokeBySessionId = repo.revokeBySessionId;
  },
}));
vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), error: vi.fn(), warn: vi.fn(), debug: vi.fn() },
}));

const { default: kcwKeysRouter } = await import("./kcw-keys");

const TOKEN = "t".repeat(40);
let server: ReturnType<express.Express["listen"]>;
let base: string;

beforeAll(async () => {
  const app = express();
  app.use(express.json());
  app.use("/internal/kcw", kcwKeysRouter);
  await new Promise<void>((resolve) => {
    server = app.listen(0, () => resolve());
  });
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}/internal/kcw`;
});
afterAll(() => server.close());

beforeEach(() => {
  vi.stubEnv("KCW_SERVICE_TOKEN", TOKEN);
  vi.stubEnv("KCW_KEY_OWNER_USER_ID", "");
  repo.createSessionKey.mockReset().mockResolvedValue({
    key: "sk_mt_secret",
    key_uuid: "6f1c1c1e-8b1d-4f5e-9a55-0e2d3f4a5b6c",
    expires_at: new Date("2030-01-01T00:00:00Z"),
  });
  repo.revokeBySessionId.mockReset().mockResolvedValue(true);
});

const call = (method: string, path: string, body?: unknown, token = TOKEN) =>
  fetch(`${base}${path}`, {
    method,
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });

describe("POST /internal/kcw/keys", () => {
  it("is refused without the service token", async () => {
    const res = await call("POST", "/keys", { session_id: "s1" }, "wrong");
    expect(res.status).toBe(401);
    expect(repo.createSessionKey).not.toHaveBeenCalled();
  });

  it("mints a key and returns it once", async () => {
    const res = await call("POST", "/keys", {
      session_id: "s1",
      endpoint_names: ["ep"],
    });
    expect(res.status).toBe(201);
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(await res.json()).toEqual({
      key: "sk_mt_secret",
      key_uuid: "6f1c1c1e-8b1d-4f5e-9a55-0e2d3f4a5b6c",
      expires_at: "2030-01-01T00:00:00.000Z",
    });
    expect(repo.createSessionKey).toHaveBeenCalledWith({
      session_id: "s1",
      ttl_seconds: 3600,
      user_id: null,
      endpoint_names: ["ep"],
    });
  });

  it.each([
    [undefined, 3600],
    [60, 60],
    [3600, 3600],
    [99999, 3600],
  ])("ttl_seconds %s becomes %s", async (ttl, expected) => {
    await call("POST", "/keys", { session_id: "s1", ttl_seconds: ttl });
    expect(repo.createSessionKey.mock.calls[0][0].ttl_seconds).toBe(expected);
  });

  it("uses the configured owner", async () => {
    vi.stubEnv("KCW_KEY_OWNER_USER_ID", "owner-1");
    await call("POST", "/keys", { session_id: "s1" });
    expect(repo.createSessionKey.mock.calls[0][0].user_id).toBe("owner-1");
  });

  it.each([
    {},
    { session_id: "" },
    { session_id: "a/b" },
    { session_id: "x".repeat(129) },
    { session_id: "s", ttl_seconds: 0 },
    { session_id: "s", ttl_seconds: -5 },
    { session_id: "s", ttl_seconds: 1.5 },
    { session_id: "s", endpoint_names: [""] },
  ])("rejects invalid body %j", async (body) => {
    expect((await call("POST", "/keys", body)).status).toBe(400);
    expect(repo.createSessionKey).not.toHaveBeenCalled();
  });

  it("does not leak internal errors", async () => {
    repo.createSessionKey.mockRejectedValue(new Error("db password leaked"));
    const res = await call("POST", "/keys", { session_id: "s1" });
    expect(res.status).toBe(500);
    expect(JSON.stringify(await res.json())).not.toContain("leaked");
  });
});

describe("DELETE /internal/kcw/keys/:sessionId", () => {
  it("revokes, and is idempotent", async () => {
    expect((await call("DELETE", "/keys/s1")).status).toBe(204);
    repo.revokeBySessionId.mockResolvedValue(false);
    expect((await call("DELETE", "/keys/s1")).status).toBe(204);
    expect(repo.revokeBySessionId).toHaveBeenCalledWith("s1");
  });

  it("rejects a malformed session id and a wrong token", async () => {
    expect((await call("DELETE", "/keys/a%20b")).status).toBe(400);
    expect((await call("DELETE", "/keys/s1", undefined, "bad")).status).toBe(
      401,
    );
  });
});
