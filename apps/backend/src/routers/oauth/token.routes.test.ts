import crypto from "node:crypto";
import type { AddressInfo } from "node:net";

import express from "express";
import {
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";

import { hashClientSecretForStorage, sha256Hex } from "../../lib/secret-hash";

const repo = vi.hoisted(() => ({
  getClient: vi.fn(),
  consumeAuthCode: vi.fn(),
  setAccessToken: vi.fn(),
  getByRefreshToken: vi.fn(),
  deleteAccessTokenByHash: vi.fn(),
  deleteAccessToken: vi.fn(),
  getAccessToken: vi.fn(),
  upgradeClientSecret: vi.fn(),
}));
vi.mock("../../db/repositories", () => ({ oauthRepository: repo }));
vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

import tokenRouter from "./token";

let server: ReturnType<express.Express["listen"]>;
let base: string;

beforeAll(async () => {
  const app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  app.use(tokenRouter);
  await new Promise<void>((resolve) => {
    server = app.listen(0, "127.0.0.1", () => resolve());
  });
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

const VERIFIER = "v".repeat(50);
const CHALLENGE = crypto
  .createHash("sha256")
  .update(VERIFIER)
  .digest("base64url");
const REDIRECT = "https://client.example/cb";

const codeRow = (clientId = "cid") => ({
  client_id: clientId,
  redirect_uri: REDIRECT,
  scope: "admin",
  user_id: "u1",
  code_challenge: CHALLENGE,
  code_challenge_method: "S256",
  expires_at: new Date(Date.now() + 60_000),
});

const post = (
  body: Record<string, unknown>,
  headers: Record<string, string> = {},
) =>
  fetch(base + "/oauth/token", {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body),
  });

const redeem = (extra: Record<string, unknown> = {}, headers = {}) =>
  post(
    {
      grant_type: "authorization_code",
      code: "mcp_code_x",
      client_id: "cid",
      redirect_uri: REDIRECT,
      code_verifier: VERIFIER,
      ...extra,
    },
    headers,
  );

const basic = (id: string, secret: string) => ({
  Authorization: "Basic " + Buffer.from(`${id}:${secret}`).toString("base64"),
});

beforeEach(() => {
  vi.clearAllMocks();
  repo.setAccessToken.mockResolvedValue(undefined);
  repo.upgradeClientSecret.mockResolvedValue(undefined);
});

// the token endpoint is rate limited per IP (20/min): keep each test's traffic small

describe("authorization_code grant", () => {
  it("lets exactly one of several concurrent redemptions of a code succeed", async () => {
    repo.getClient.mockResolvedValue({
      client_id: "cid",
      token_endpoint_auth_method: "none",
    });
    // atomic single-use semantics of DELETE ... RETURNING
    let available = true;
    repo.consumeAuthCode.mockImplementation(async () => {
      if (!available) return null;
      available = false;
      return codeRow();
    });

    const responses = await Promise.all(
      Array.from({ length: 6 }, () => redeem()),
    );
    const statuses = responses.map((r) => r.status).sort();
    expect(statuses).toEqual([200, 400, 400, 400, 400, 400]);
    expect(repo.setAccessToken).toHaveBeenCalledTimes(1);
  });

  it("burns the code when client authentication fails", async () => {
    repo.getClient.mockResolvedValue({
      client_id: "cid",
      token_endpoint_auth_method: "client_secret_basic",
      client_secret: hashClientSecretForStorage("right"),
    });
    repo.consumeAuthCode.mockResolvedValue(codeRow());
    const r = await redeem({}, basic("cid", "wrong"));
    expect(r.status).toBe(401);
    expect(repo.consumeAuthCode).toHaveBeenCalledTimes(1);
    expect(repo.setAccessToken).not.toHaveBeenCalled();
  });

  it("accepts Basic credentials whose secret contains ':' and ones that are form-urlencoded", async () => {
    const secret = "mcp_secret:with:colons";
    repo.getClient.mockResolvedValue({
      client_id: "cid",
      token_endpoint_auth_method: "client_secret_basic",
      client_secret: hashClientSecretForStorage(secret),
    });
    repo.consumeAuthCode.mockResolvedValue(codeRow());
    expect((await redeem({}, basic("cid", secret))).status).toBe(200);

    repo.consumeAuthCode.mockResolvedValue(codeRow());
    const encoded =
      "Basic " +
      Buffer.from(`cid:${encodeURIComponent(secret)}`).toString("base64");
    expect((await redeem({}, { Authorization: encoded })).status).toBe(200);
  });

  it("upgrades a legacy plaintext client secret to its hash after the first success", async () => {
    repo.getClient.mockResolvedValue({
      client_id: "cid",
      token_endpoint_auth_method: "client_secret_post",
      client_secret: "legacy-plain-secret",
    });
    repo.consumeAuthCode.mockResolvedValue(codeRow());
    const r = await redeem({ client_secret: "legacy-plain-secret" });
    expect(r.status).toBe(200);
    expect(repo.upgradeClientSecret).toHaveBeenCalledWith(
      "cid",
      hashClientSecretForStorage("legacy-plain-secret"),
    );
  });

  it("does not touch secrets that are already hashed, nor upgrade after a failure", async () => {
    repo.getClient.mockResolvedValue({
      client_id: "cid",
      token_endpoint_auth_method: "client_secret_post",
      client_secret: hashClientSecretForStorage("s3"),
    });
    repo.consumeAuthCode.mockResolvedValue(codeRow());
    expect((await redeem({ client_secret: "s3" })).status).toBe(200);
    expect(repo.upgradeClientSecret).not.toHaveBeenCalled();

    repo.getClient.mockResolvedValue({
      client_id: "cid",
      token_endpoint_auth_method: "client_secret_post",
      client_secret: "legacy",
    });
    repo.consumeAuthCode.mockResolvedValue(codeRow());
    expect((await redeem({ client_secret: "wrong" })).status).toBe(401);
    expect(repo.upgradeClientSecret).not.toHaveBeenCalled();
  });
});

describe("refresh_token grant", () => {
  const tokenRow = (clientId = "cid") => ({
    access_token: sha256Hex("mcp_token_old"),
    client_id: clientId,
    user_id: "u1",
    scope: "admin",
    expires_at: new Date(Date.now() + 1000),
    refresh_token: sha256Hex("mcp_refresh_old"),
    refresh_token_expires_at: new Date(Date.now() + 60_000),
  });
  const refresh = (extra: Record<string, unknown> = {}, headers = {}) =>
    post(
      {
        grant_type: "refresh_token",
        refresh_token: "mcp_refresh_old",
        ...extra,
      },
      headers,
    );

  it("refuses to refresh under a different client_id (RFC 6749 6)", async () => {
    repo.getByRefreshToken.mockResolvedValue(tokenRow("cid"));
    repo.getClient.mockResolvedValue({
      client_id: "cid",
      token_endpoint_auth_method: "none",
    });
    const r = await refresh({ client_id: "someone-else" });
    expect(r.status).toBe(400);
    expect(repo.deleteAccessTokenByHash).not.toHaveBeenCalled();
    expect(repo.setAccessToken).not.toHaveBeenCalled();
  });

  it("requires a confidential client to authenticate, and a failed attempt keeps the token", async () => {
    repo.getByRefreshToken.mockResolvedValue(tokenRow());
    repo.getClient.mockResolvedValue({
      client_id: "cid",
      token_endpoint_auth_method: "client_secret_basic",
      client_secret: hashClientSecretForStorage("right"),
    });
    expect((await refresh()).status).toBe(401);
    expect((await refresh({}, basic("cid", "wrong"))).status).toBe(401);
    expect(repo.deleteAccessTokenByHash).not.toHaveBeenCalled();

    const ok = await refresh({}, basic("cid", "right"));
    expect(ok.status).toBe(200);
    expect(repo.deleteAccessTokenByHash).toHaveBeenCalledWith(
      sha256Hex("mcp_token_old"),
    );
  });

  it("public clients refresh with just the token (and optionally their client_id)", async () => {
    repo.getByRefreshToken.mockResolvedValue(tokenRow());
    repo.getClient.mockResolvedValue({
      client_id: "cid",
      token_endpoint_auth_method: "none",
    });
    expect((await refresh({ client_id: "cid" })).status).toBe(200);
  });
});
