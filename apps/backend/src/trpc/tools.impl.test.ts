import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  findByUuid: vi.fn(),
  findByMcpServerUuid: vi.fn(),
  bulkUpsert: vi.fn(),
  syncTools: vi.fn(),
  canMutate: vi.fn(),
}));

vi.mock("../db/repositories", () => ({
  mcpServersRepository: { findByUuid: mocks.findByUuid },
  toolsRepository: {
    findByMcpServerUuid: mocks.findByMcpServerUuid,
    bulkUpsert: mocks.bulkUpsert,
    syncTools: mocks.syncTools,
  },
}));
vi.mock("../lib/authz", () => ({ canMutate: mocks.canMutate }));
vi.mock("../lib/metamcp/tools-sync-cache", () => ({
  toolsSyncCache: { hasChanged: () => true, update: vi.fn() },
}));
vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), error: vi.fn(), warn: vi.fn(), debug: vi.fn() },
}));

import { toolsImplementations as impl } from "./tools.impl";

const SERVER = "11111111-1111-4111-8111-111111111111";
const tools = [
  { name: "t", description: "d", inputSchema: { type: "object" as const } },
];

beforeEach(() => {
  vi.clearAllMocks();
  mocks.findByMcpServerUuid.mockResolvedValue([]);
  mocks.bulkUpsert.mockResolvedValue([{}]);
  mocks.syncTools.mockResolvedValue({ upserted: [{}], deleted: [] });
});

describe("tools access control", () => {
  it("reads: denies another user's private server", async () => {
    mocks.findByUuid.mockResolvedValue({ uuid: SERVER, user_id: "owner" });
    const r = await impl.getByMcpServerUuid({ mcpServerUuid: SERVER }, "other");
    expect(r.success).toBe(false);
    expect(mocks.findByMcpServerUuid).not.toHaveBeenCalled();
  });

  it("reads: allows own and shared servers", async () => {
    mocks.findByUuid.mockResolvedValue({ uuid: SERVER, user_id: "me" });
    expect(
      (await impl.getByMcpServerUuid({ mcpServerUuid: SERVER }, "me")).success,
    ).toBe(true);
    mocks.findByUuid.mockResolvedValue({ uuid: SERVER, user_id: null });
    expect(
      (await impl.getByMcpServerUuid({ mcpServerUuid: SERVER }, "me")).success,
    ).toBe(true);
  });

  it("reads: unknown server", async () => {
    mocks.findByUuid.mockResolvedValue(undefined);
    const r = await impl.getByMcpServerUuid({ mcpServerUuid: SERVER }, "me");
    expect(r).toMatchObject({
      success: false,
      message: "MCP server not found",
    });
  });

  it.each(["create", "sync"] as const)(
    "%s: needs canMutate on the server",
    async (fn) => {
      mocks.findByUuid.mockResolvedValue({ uuid: SERVER, user_id: "owner" });
      mocks.canMutate.mockResolvedValue(false);
      const denied = await impl[fn]({ mcpServerUuid: SERVER, tools }, "other");
      expect(denied.success).toBe(false);
      expect(mocks.bulkUpsert).not.toHaveBeenCalled();
      expect(mocks.syncTools).not.toHaveBeenCalled();
      expect(mocks.canMutate).toHaveBeenCalledWith("owner", "other");

      mocks.canMutate.mockResolvedValue(true);
      const ok = await impl[fn]({ mcpServerUuid: SERVER, tools }, "owner");
      expect(ok.success).toBe(true);
    },
  );
});
