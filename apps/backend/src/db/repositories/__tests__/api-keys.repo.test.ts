import { beforeEach, describe, expect, it, vi } from "vitest";

import { apiKeyPrefix, hashApiKey } from "../../../lib/api-key-hash";

// A tiny fake of the drizzle query builder that records what is written and
// answers selects from a queue, so the repository's own logic can be checked.
const state = vi.hoisted(() => ({
  inserted: [] as Array<Record<string, unknown>>,
  updated: [] as Array<Record<string, unknown>>,
  selectResults: [] as unknown[][],
  selectShapes: [] as unknown[],
  wheres: [] as unknown[],
  deleted: 0,
  revokedRows: [] as unknown[],
}));

vi.mock("../../index", () => {
  const select = (shape: unknown) => {
    state.selectShapes.push(shape);
    const result = () => Promise.resolve(state.selectResults.shift() ?? []);
    const chain: Record<string, unknown> = {};
    chain.from = () => chain;
    chain.where = (w: unknown) => {
      state.wheres.push(w);
      return chain;
    };
    chain.orderBy = result;
    chain.limit = result;
    chain.then = (res: (v: unknown) => unknown, rej: (e: unknown) => unknown) =>
      result().then(res, rej);
    return chain;
  };
  const db = {
    select,
    insert: () => ({
      values: (v: Record<string, unknown>) => {
        state.inserted.push(v);
        return {
          returning: () =>
            Promise.resolve([
              {
                uuid: "u-1",
                name: v.name,
                user_id: v.user_id ?? null,
                created_at: new Date(),
                expires_at: new Date("2030-01-01T00:00:00Z"),
              },
            ]),
        };
      },
    }),
    update: () => ({
      set: (v: Record<string, unknown>) => {
        state.updated.push(v);
        return {
          where: (w: unknown) => {
            state.wheres.push(w);
            const p = Promise.resolve() as Promise<void> & {
              returning?: () => Promise<unknown[]>;
            };
            p.returning = () => Promise.resolve(state.revokedRows);
            return p;
          },
        };
      },
    }),
    delete: () => ({
      where: (w: unknown) => {
        state.wheres.push(w);
        return {
          returning: () =>
            Promise.resolve(Array.from({ length: state.deleted }, () => ({}))),
        };
      },
    }),
    transaction: (fn: (tx: unknown) => unknown) => fn(db),
  };
  return { db };
});

const { ApiKeysRepository } = await import("../api-keys.repo");
const { apiKeysTable } = await import("../../schema");

// Collect the literal parameter values inside a drizzle condition
const paramsOf = (node: unknown, out: unknown[] = []): unknown[] => {
  if (!node || typeof node !== "object") return out;
  const n = node as {
    queryChunks?: unknown[];
    value?: unknown;
    constructor?: { name?: string };
  };
  if (n.constructor?.name === "Param") out.push(n.value);
  if (Array.isArray(n.queryChunks))
    n.queryChunks.forEach((c) => paramsOf(c, out));
  return out;
};

beforeEach(() => {
  state.inserted.length = 0;
  state.updated.length = 0;
  state.selectResults.length = 0;
  state.selectShapes.length = 0;
  state.wheres.length = 0;
  state.deleted = 0;
  state.revokedRows.length = 0;
});

describe("ApiKeysRepository", () => {
  const repo = new ApiKeysRepository();

  it("create stores only the hash and the prefix, and returns the plaintext once", async () => {
    const created = await repo.create({
      name: "k",
      user_id: "u1",
      is_active: true,
    });

    expect(created.key).toMatch(/^sk_mt_[0-9A-Za-z]{64}$/);
    const row = state.inserted[0];
    expect(row.key).toBe(hashApiKey(created.key));
    expect(row.key).not.toBe(created.key);
    expect(row.key_prefix).toBe(apiKeyPrefix(created.key));
    expect(JSON.stringify(row)).not.toContain(created.key);
  });

  it("validateApiKey hashes the presented key before looking it up", async () => {
    state.selectResults.push([{ uuid: "k1", user_id: "u1", is_active: true }]);
    const r = await repo.validateApiKey("sk_mt_presented");

    expect(r).toEqual({ valid: true, user_id: "u1", key_uuid: "k1" });
    const params = paramsOf(state.wheres[0]);
    expect(params).toContain(hashApiKey("sk_mt_presented"));
    expect(params).not.toContain("sk_mt_presented");
    expect(state.updated).toHaveLength(0);
  });

  it("rejects unknown, and inactive keys", async () => {
    expect((await repo.validateApiKey("nope")).valid).toBe(false);
    state.selectResults.push([{ uuid: "k1", user_id: "u1", is_active: false }]);
    expect((await repo.validateApiKey("sk_mt_x")).valid).toBe(false);
  });

  it("accepts a plaintext row left by an older instance once and converts it to the hash", async () => {
    const legacy = "sk_mt_" + "L".repeat(64);
    state.selectResults.push(
      [],
      [{ uuid: "k2", user_id: null, is_active: true }],
    );
    const r = await repo.validateApiKey(legacy);

    expect(r).toEqual({ valid: true, user_id: null, key_uuid: "k2" });
    expect(paramsOf(state.wheres[1])).toEqual(
      expect.arrayContaining([legacy, ""]),
    );
    expect(state.updated[0]).toEqual({
      key: hashApiKey(legacy),
      key_prefix: apiKeyPrefix(legacy),
    });
  });

  it("listings select the display value, never the stored hash", async () => {
    await repo.findAccessibleToUser("u1");
    await repo.findAll();
    await repo.findPublicApiKeys();
    for (const shape of state.selectShapes) {
      const key = (shape as { key: unknown }).key;
      expect(key).toBeDefined();
      expect(key).not.toBe(apiKeysTable.key);
    }
  });

  it("rejects revoked and expired keys, also when found through the legacy plaintext path", async () => {
    const base = { uuid: "k1", user_id: "u1", is_active: true };
    state.selectResults.push([{ ...base, revoked_at: new Date() }]);
    expect((await repo.validateApiKey("sk_mt_a")).valid).toBe(false);

    state.selectResults.push([{ ...base, expired: true }]);
    expect((await repo.validateApiKey("sk_mt_b")).valid).toBe(false);

    state.selectResults.push([], [{ ...base, expired: true }]);
    expect((await repo.validateApiKey("sk_mt_c")).valid).toBe(false);

    state.selectResults.push([{ ...base, expired: false, revoked_at: null }]);
    expect((await repo.validateApiKey("sk_mt_d")).valid).toBe(true);
  });

  it("validateApiKey returns the session and the endpoint scope", async () => {
    state.selectResults.push([
      {
        uuid: "k1",
        user_id: null,
        is_active: true,
        session_id: "s1",
        endpoint_names: ["ep"],
      },
    ]);
    expect(await repo.validateApiKey("sk_mt_x")).toMatchObject({
      valid: true,
      session_id: "s1",
      endpoint_names: ["ep"],
    });
  });

  it("createSessionKey revokes the session's earlier key, then stores only the hash", async () => {
    const r = await repo.createSessionKey({
      session_id: "sess-1",
      ttl_seconds: 3600,
      user_id: null,
      endpoint_names: ["ep"],
    });

    expect(r.key).toMatch(/^sk_mt_[0-9A-Za-z]{64}$/);
    expect(r.key_uuid).toBe("u-1");
    expect(r.expires_at).toBeInstanceOf(Date);
    expect(state.updated[0]).toHaveProperty("revoked_at");
    const row = state.inserted[0];
    expect(row.key).toBe(hashApiKey(r.key));
    expect(row.session_id).toBe("sess-1");
    expect(row.endpoint_names).toEqual(["ep"]);
    expect(String(row.name)).toMatch(/^kcw-session-sess-1-/);
    expect(JSON.stringify(row)).not.toContain(r.key);
  });

  it("createSessionKey without a scope stores NULL endpoint_names", async () => {
    await repo.createSessionKey({
      session_id: "s",
      ttl_seconds: 10,
      user_id: "u1",
    });
    expect(state.inserted[0].endpoint_names).toBeNull();
  });

  it("revokeBySessionId reports whether a live key existed", async () => {
    expect(await repo.revokeBySessionId("s")).toBe(false);
    state.revokedRows.push({ uuid: "k" });
    expect(await repo.revokeBySessionId("s")).toBe(true);
    expect(paramsOf(state.wheres[0])).toContain("s");
  });

  it("deleteExpiredSessionKeys returns the number of deleted keys", async () => {
    state.deleted = 3;
    expect(await repo.deleteExpiredSessionKeys(new Date())).toBe(3);
  });
});
