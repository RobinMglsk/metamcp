import { beforeEach, describe, expect, it, vi } from "vitest";

import { sha256Hex } from "../../../lib/secret-hash";

const state = vi.hoisted(() => ({
  selectResults: [] as unknown[][],
  updated: [] as Array<Record<string, unknown>>,
  selects: 0,
}));

vi.mock("../../index", () => {
  const select = () => {
    state.selects++;
    const result = () => Promise.resolve(state.selectResults.shift() ?? []);
    const chain: Record<string, unknown> = {};
    chain.from = () => chain;
    chain.where = () => chain;
    chain.limit = result;
    return chain;
  };
  return {
    db: {
      select,
      update: () => ({
        set: (v: Record<string, unknown>) => {
          state.updated.push(v);
          return { where: () => Promise.resolve() };
        },
      }),
    },
  };
});

const { oauthRepository } = await import("../oauth.repo");

const row = (over = {}) => ({
  access_token: "mcp_token_legacy",
  client_id: "c",
  user_id: "u",
  scope: "admin",
  expires_at: new Date(Date.now() + 1000),
  refresh_token: "mcp_refresh_legacy",
  refresh_token_expires_at: new Date(Date.now() + 1000),
  created_at: new Date(),
  ...over,
});

beforeEach(() => {
  state.selectResults.length = 0;
  state.updated.length = 0;
  state.selects = 0;
});

describe("tokens issued before hashing", () => {
  it("an access token stored in plaintext is honoured once and hashed in place", async () => {
    state.selectResults.push([], [row()]);
    const found = await oauthRepository.getAccessToken("mcp_token_legacy");

    expect(found?.access_token).toBe(sha256Hex("mcp_token_legacy"));
    expect(found?.refresh_token).toBe(sha256Hex("mcp_refresh_legacy"));
    expect(state.updated[0]).toEqual({
      access_token: sha256Hex("mcp_token_legacy"),
      refresh_token: sha256Hex("mcp_refresh_legacy"),
    });
  });

  it("a plaintext refresh token is honoured and upgraded too", async () => {
    state.selectResults.push([], [row()]);
    const found = await oauthRepository.getByRefreshToken("mcp_refresh_legacy");
    expect(found?.refresh_token).toBe(sha256Hex("mcp_refresh_legacy"));
    expect(state.updated).toHaveLength(1);
  });

  it("an already hashed row is returned without any plaintext fallback", async () => {
    state.selectResults.push([
      row({ access_token: sha256Hex("mcp_token_new") }),
    ]);
    await oauthRepository.getAccessToken("mcp_token_new");
    expect(state.selects).toBe(1);
    expect(state.updated).toHaveLength(0);
  });

  it("a stored hash cannot be presented as a token (no plaintext lookup for non-prefixed values)", async () => {
    const hash = sha256Hex("mcp_token_victim");
    expect(await oauthRepository.getAccessToken(hash)).toBeNull();
    expect(await oauthRepository.getByRefreshToken(hash)).toBeNull();
    expect(state.selects).toBe(2); // one hashed lookup each, never a plaintext one
  });
});
