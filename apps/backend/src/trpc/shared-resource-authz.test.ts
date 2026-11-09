import { beforeEach, describe, expect, it, vi } from "vitest";

// The real authz module runs; only the database lookup of the caller's role is
// faked: ADMIN_IDS decides who is an administrator.
const ADMIN_IDS = new Set(["admin"]);
const mocks = vi.hoisted(() => ({
  limit: vi.fn(),
  server: { findByUuid: vi.fn(), deleteByUuid: vi.fn(), update: vi.fn() },
  mappings: { findNamespacesByServerUuid: vi.fn() },
  namespace: { findByUuid: vi.fn(), deleteByUuid: vi.fn() },
  endpoint: { findByUuidWithNamespace: vi.fn(), deleteByUuid: vi.fn() },
  keys: { update: vi.fn(), delete: vi.fn(), findAccessibleToUser: vi.fn() },
}));

vi.mock("../db", () => ({
  db: {
    select: () => ({
      from: () => ({ where: () => ({ limit: mocks.limit }) }),
    }),
  },
}));
vi.mock("../db/repositories", () => ({
  mcpServersRepository: mocks.server,
  namespaceMappingsRepository: mocks.mappings,
  namespacesRepository: mocks.namespace,
  endpointsRepository: mocks.endpoint,
  oauthSessionsRepository: {},
  ApiKeysRepository: class {
    update = mocks.keys.update;
    deleteByName = vi.fn().mockResolvedValue(undefined);
    delete = mocks.keys.delete;
    findAccessibleToUser = mocks.keys.findAccessibleToUser;
  },
}));
vi.mock("../lib/metamcp/mcp-server-pool", () => ({
  mcpServerPool: { cleanupIdleSession: vi.fn() },
}));
vi.mock("../lib/metamcp/metamcp-server-pool", () => ({
  metaMcpServerPool: {
    invalidateIdleServers: vi.fn().mockResolvedValue(undefined),
    invalidateOpenApiSessions: vi.fn().mockResolvedValue(undefined),
    cleanupIdleServer: vi.fn().mockResolvedValue(undefined),
  },
}));
vi.mock("../lib/metamcp/metamcp-middleware/tool-overrides.functional", () => ({
  clearOverrideCache: vi.fn(),
}));
vi.mock("../lib/metamcp/server-error-tracker", () => ({
  serverErrorTracker: {},
}));
vi.mock("../lib/metamcp/utils", () => ({
  convertDbServerToParams: vi.fn().mockResolvedValue(null),
}));
vi.mock("../lib/server-url-policy", () => ({
  checkMcpServerUrl: vi.fn().mockResolvedValue(null),
}));
vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), error: vi.fn(), warn: vi.fn(), debug: vi.fn() },
}));

import { apiKeysImplementations } from "./api-keys.impl";
import { endpointsImplementations } from "./endpoints.impl";
import { mcpServersImplementations } from "./mcp-servers.impl";
import { namespacesImplementations } from "./namespaces.impl";

const UUID = "11111111-1111-4111-8111-111111111111";
const SHARED = /shared \(public\) resources/;

beforeEach(() => {
  vi.clearAllMocks();
  // which user is asking is passed as the userId argument; the fake db answers
  // with the role of whoever authz looked up last
  mocks.limit.mockImplementation(async () => [{ role: currentRole }]);
});

let currentRole = "user";
const as = (id: string) => {
  currentRole = ADMIN_IDS.has(id) ? "admin" : "user";
  return id;
};

describe("shared (user_id = null) resources are admin-only to modify", () => {
  it("servers: delete", async () => {
    mocks.server.findByUuid.mockResolvedValue({
      uuid: UUID,
      user_id: null,
      name: "s",
    });
    mocks.mappings.findNamespacesByServerUuid.mockResolvedValue([]);
    mocks.server.deleteByUuid.mockResolvedValue({ uuid: UUID, name: "s" });

    const denied = await mcpServersImplementations.delete(
      { uuid: UUID },
      as("user-1"),
    );
    expect(denied).toMatchObject({ success: false });
    expect((denied as { message: string }).message).toMatch(SHARED);
    expect(mocks.server.deleteByUuid).not.toHaveBeenCalled();

    const ok = await mcpServersImplementations.delete(
      { uuid: UUID },
      as("admin"),
    );
    expect(ok.success).toBe(true);
    expect(mocks.server.deleteByUuid).toHaveBeenCalledTimes(1);
  });

  it("servers: update", async () => {
    mocks.server.findByUuid.mockResolvedValue({
      uuid: UUID,
      user_id: null,
      type: "SSE",
    });
    const denied = await mcpServersImplementations.update(
      {
        uuid: UUID,
        name: "x",
        type: "SSE",
        url: "https://a.example/sse",
      } as never,
      as("user-1"),
    );
    expect(denied).toMatchObject({ success: false });
    expect(mocks.server.update).not.toHaveBeenCalled();
  });

  it("servers: another user's private server keeps the owner message", async () => {
    mocks.server.findByUuid.mockResolvedValue({
      uuid: UUID,
      user_id: "owner",
      type: "SSE",
    });
    const r = await mcpServersImplementations.delete(
      { uuid: UUID },
      as("user-1"),
    );
    expect((r as { message: string }).message).toMatch(/you own/);
  });

  it("namespaces: delete", async () => {
    mocks.namespace.findByUuid.mockResolvedValue({ uuid: UUID, user_id: null });
    mocks.namespace.deleteByUuid.mockResolvedValue({ uuid: UUID, name: "n" });
    const denied = await namespacesImplementations.delete(
      { uuid: UUID },
      as("user-1"),
    );
    expect((denied as { message: string }).message).toMatch(SHARED);
    expect(mocks.namespace.deleteByUuid).not.toHaveBeenCalled();
    expect(
      (await namespacesImplementations.delete({ uuid: UUID }, as("admin")))
        .success,
    ).toBe(true);
  });

  it("namespaces: tool status changes", async () => {
    mocks.namespace.findByUuid.mockResolvedValue({ uuid: UUID, user_id: null });
    const r = await namespacesImplementations.updateToolStatus(
      {
        namespaceUuid: UUID,
        toolUuid: UUID,
        serverUuid: UUID,
        status: "INACTIVE",
      } as never,
      as("user-1"),
    );
    expect(r).toMatchObject({ success: false });
  });

  it("endpoints: delete", async () => {
    mocks.endpoint.findByUuidWithNamespace.mockResolvedValue({
      uuid: UUID,
      user_id: null,
    });
    mocks.endpoint.deleteByUuid.mockResolvedValue({ uuid: UUID, name: "e" });
    const denied = await endpointsImplementations.delete(
      { uuid: UUID },
      as("user-1"),
    );
    expect((denied as { message: string }).message).toMatch(SHARED);
    expect(mocks.endpoint.deleteByUuid).not.toHaveBeenCalled();
    expect(
      (await endpointsImplementations.delete({ uuid: UUID }, as("admin")))
        .success,
    ).toBe(true);
  });

  it("api keys: only admins may change or delete shared keys", async () => {
    mocks.keys.update.mockResolvedValue({
      uuid: UUID,
      name: "k",
      key: "sk_mt_x",
      created_at: new Date(),
      is_active: true,
    });
    mocks.keys.delete.mockResolvedValue({ uuid: UUID, name: "k" });

    await apiKeysImplementations.update(
      { uuid: UUID, name: "k" } as never,
      as("user-1"),
    );
    expect(mocks.keys.update.mock.calls[0][3]).toBe(false);
    await apiKeysImplementations.update(
      { uuid: UUID, name: "k" } as never,
      as("admin"),
    );
    expect(mocks.keys.update.mock.calls[1][3]).toBe(true);

    await apiKeysImplementations.delete({ uuid: UUID }, as("user-1"));
    expect(mocks.keys.delete.mock.calls[0][2]).toBe(false);
    await apiKeysImplementations.delete({ uuid: UUID }, as("admin"));
    expect(mocks.keys.delete.mock.calls[1][2]).toBe(true);
  });

  it("api keys: the secret of a shared key is only listed for admins", async () => {
    const key = "sk_mt_" + "A".repeat(64);
    mocks.keys.findAccessibleToUser.mockResolvedValue([
      {
        uuid: "1",
        name: "shared",
        key,
        created_at: new Date(),
        is_active: true,
        user_id: null,
      },
      {
        uuid: "2",
        name: "mine",
        key: key + "B",
        created_at: new Date(),
        is_active: true,
        user_id: "user-1",
      },
    ]);
    const asUser = await apiKeysImplementations.list(as("user-1"));
    const shared = asUser.apiKeys.find((k) => k.name === "shared");
    const mine = asUser.apiKeys.find((k) => k.name === "mine");
    expect(shared?.key).toBe(key.slice(0, 12) + "…");
    expect(
      JSON.stringify(asUser.apiKeys.find((k) => k.name === "shared")),
    ).not.toContain(key);
    expect(mine?.key).toBe(key + "B");

    const asAdmin = await apiKeysImplementations.list(as("admin"));
    expect(asAdmin.apiKeys.find((k) => k.name === "shared")?.key).toBe(key);
  });
});
