import type { AddressInfo } from "node:net";

import express from "express";
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";

const repo = vi.hoisted(() => ({ upsertClient: vi.fn() }));
vi.mock("../../db/repositories", () => ({ oauthRepository: repo }));
vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

import registrationRouter from "./registration";

let server: ReturnType<express.Express["listen"]>;
let base: string;

beforeAll(async () => {
  const app = express();
  app.set("trust proxy", true); // so X-Forwarded-For selects the "client" in these tests
  app.use(express.json());
  app.use(registrationRouter);
  await new Promise<void>((resolve) => {
    server = app.listen(0, "127.0.0.1", () => resolve());
  });
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

beforeEach(() => {
  vi.clearAllMocks();
  repo.upsertClient.mockResolvedValue(undefined);
});
afterEach(() => {
  delete process.env.OAUTH_REGISTRATION_ENABLED;
});

const register = (
  headers: Record<string, string> = {},
  body: unknown = {
    redirect_uris: ["https://client.example/cb"],
    client_name: "App",
  },
) =>
  fetch(base + "/oauth/register", {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body),
  });

describe("POST /oauth/register", () => {
  it("answers 403 and stores nothing when registration is disabled", async () => {
    process.env.OAUTH_REGISTRATION_ENABLED = "false";
    const r = await register({ "X-Forwarded-For": "198.51.100.1" });
    expect(r.status).toBe(403);
    expect(await r.json()).toMatchObject({ error: "access_denied" });
    expect(repo.upsertClient).not.toHaveBeenCalled();
  });

  it("registers a client when enabled and stores a sanitised name", async () => {
    const r = await register(
      { "X-Forwarded-For": "198.51.100.2" },
      {
        redirect_uris: ["https://client.example/cb"],
        client_name: " A\u0000pp ",
      },
    );
    expect(r.status).toBe(201);
    expect(repo.upsertClient).toHaveBeenCalledWith(
      expect.objectContaining({ client_name: "App" }),
    );
  });

  it("rejects oversized metadata before storing anything", async () => {
    const r = await register(
      { "X-Forwarded-For": "198.51.100.3" },
      {
        redirect_uris: ["https://client.example/cb"],
        client_name: "x".repeat(101),
      },
    );
    expect(r.status).toBe(400);
    expect(repo.upsertClient).not.toHaveBeenCalled();
  });
});

describe("registration rate limit", () => {
  it("allows 30 per hour per client address, then 429, without affecting other clients", async () => {
    const abuser = { "X-Forwarded-For": "203.0.113.50" };
    const statuses: number[] = [];
    for (let i = 0; i < 31; i++) statuses.push((await register(abuser)).status);
    expect(statuses.slice(0, 30).every((s) => s === 201)).toBe(true);
    expect(statuses[30]).toBe(429);

    expect((await register({ "X-Forwarded-For": "203.0.113.51" })).status).toBe(
      201,
    );
  });

  it("gives the shared loopback bucket (no TRUST_PROXY behind the bundled proxy) a much higher ceiling", async () => {
    // no X-Forwarded-For: the client is 127.0.0.1, like every client behind the Next.js proxy
    const statuses: number[] = [];
    for (let i = 0; i < 40; i++) statuses.push((await register()).status);
    expect(statuses.every((s) => s === 201)).toBe(true); // 40 > the per-client limit of 30
  });

  it("still stops a flood from the shared bucket at 300 per hour", async () => {
    let limited = 0;
    for (let i = 0; i < 270; i++) {
      if ((await register()).status === 429) limited++;
    }
    // 40 were used by the previous test; the 300th request in the window is refused
    expect(limited).toBeGreaterThan(0);
  });
});
