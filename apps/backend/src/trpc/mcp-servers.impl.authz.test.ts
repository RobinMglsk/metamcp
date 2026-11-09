import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  isAdmin: vi.fn(),
  create: vi.fn(),
  bulkCreate: vi.fn(),
  findByUuid: vi.fn(),
  update: vi.fn(),
  checkMcpServerUrl: vi.fn(),
}));

vi.mock("../lib/authz", () => ({
  isAdmin: mocks.isAdmin,
  canMutate: vi.fn().mockResolvedValue(true),
  STDIO_ADMIN_ONLY_MESSAGE: "stdio admin only",
}));
vi.mock("../lib/server-url-policy", () => ({
  checkMcpServerUrl: mocks.checkMcpServerUrl,
}));
vi.mock("../db/repositories", () => ({
  mcpServersRepository: {
    create: mocks.create,
    bulkCreate: mocks.bulkCreate,
    findByUuid: mocks.findByUuid,
    update: mocks.update,
  },
  namespaceMappingsRepository: { findNamespacesByServerUuid: vi.fn() },
  oauthSessionsRepository: {},
}));
vi.mock("../lib/metamcp/mcp-server-pool", () => ({ mcpServerPool: {} }));
vi.mock("../lib/metamcp/metamcp-server-pool", () => ({
  metaMcpServerPool: {},
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
vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), error: vi.fn(), warn: vi.fn(), debug: vi.fn() },
}));

import { mcpServersImplementations as impl } from "./mcp-servers.impl";

const stdioInput = {
  name: "evil",
  type: "STDIO" as const,
  command: "sh",
  args: ["-c", "id"],
  env: {},
};
const sseInput = {
  name: "ok",
  type: "SSE" as const,
  url: "https://x.test/sse",
};

beforeEach(() => {
  vi.clearAllMocks();
  mocks.checkMcpServerUrl.mockResolvedValue(null);
  mocks.create.mockResolvedValue({
    uuid: "u1",
    name: "n",
    type: "SSE",
    created_at: new Date(),
  });
  mocks.bulkCreate.mockResolvedValue([]);
});

describe("STDIO servers are admin-only", () => {
  it("create: rejects a non-admin creating a STDIO server", async () => {
    mocks.isAdmin.mockResolvedValue(false);
    const res = await impl.create(stdioInput as never, "user-1");
    expect(res).toMatchObject({ success: false, message: "stdio admin only" });
    expect(mocks.create).not.toHaveBeenCalled();
  });

  it("create: allows an admin to create a STDIO server", async () => {
    mocks.isAdmin.mockResolvedValue(true);
    const res = await impl.create(stdioInput as never, "admin-1");
    expect(res.success).toBe(true);
    expect(mocks.create).toHaveBeenCalled();
  });

  it("create: still lets a non-admin create HTTP-based servers", async () => {
    mocks.isAdmin.mockResolvedValue(false);
    const res = await impl.create(sseInput as never, "user-1");
    expect(res.success).toBe(true);
  });

  it("bulkImport: skips STDIO entries (including the default type) for non-admins", async () => {
    mocks.isAdmin.mockResolvedValue(false);
    const res = await impl.bulkImport(
      {
        mcpServers: {
          explicit: { type: "STDIO", command: "sh" },
          implicit: { command: "sh" },
          http: { type: "SSE", url: "https://x.test/sse" },
        },
      } as never,
      "user-1",
    );
    expect(mocks.bulkCreate).toHaveBeenCalledTimes(1);
    const inserted = mocks.bulkCreate.mock.calls[0][0];
    expect(inserted.map((s: { name: string }) => s.name)).toEqual(["http"]);
    expect(JSON.stringify(res)).toContain("stdio admin only");
  });

  it("update: rejects a non-admin updating a STDIO server", async () => {
    mocks.isAdmin.mockResolvedValue(false);
    mocks.findByUuid.mockResolvedValue({
      uuid: "u1",
      type: "SSE",
      user_id: "user-1",
    });
    const res = await impl.update(
      { uuid: "u1", ...stdioInput } as never,
      "user-1",
    );
    expect(res).toMatchObject({ success: false, message: "stdio admin only" });
    expect(mocks.update).not.toHaveBeenCalled();
  });
});

describe("server URL policy", () => {
  it("create: rejects a URL the outbound policy refuses", async () => {
    mocks.isAdmin.mockResolvedValue(false);
    mocks.checkMcpServerUrl.mockResolvedValue("Invalid server URL: private");
    const res = await impl.create(
      { name: "x", type: "SSE", url: "http://10.0.0.1/sse" } as never,
      "user-1",
    );
    expect(res).toMatchObject({
      success: false,
      message: "Invalid server URL: private",
    });
    expect(mocks.create).not.toHaveBeenCalled();
    expect(mocks.checkMcpServerUrl).toHaveBeenCalledWith(
      "http://10.0.0.1/sse",
      "user-1",
    );
  });

  it("bulkImport: reports a refused URL per entry and skips it", async () => {
    mocks.isAdmin.mockResolvedValue(false);
    mocks.checkMcpServerUrl.mockImplementation(async (url: string) =>
      url.includes("169.254") ? "Invalid server URL: metadata" : null,
    );
    const res = await impl.bulkImport(
      {
        mcpServers: {
          bad: { type: "SSE", url: "http://169.254.169.254/" },
          good: { type: "SSE", url: "https://x.example/sse" },
        },
      } as never,
      "user-1",
    );
    const inserted = mocks.bulkCreate.mock.calls[0][0];
    expect(inserted.map((s: { name: string }) => s.name)).toEqual(["good"]);
    expect(JSON.stringify(res)).toContain("metadata");
  });
});
