import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  endpointCreate: vi.fn(),
  endpointFindByName: vi.fn(),
  endpointFindWithNs: vi.fn(),
  endpointDelete: vi.fn(),
  nsFind: vi.fn(),
  serverCreate: vi.fn(),
  keyCreate: vi.fn(),
  keyDeleteByName: vi.fn(),
}));

vi.mock("../db/repositories", () => ({
  endpointsRepository: {
    create: mocks.endpointCreate,
    findByName: mocks.endpointFindByName,
    findByUuidWithNamespace: mocks.endpointFindWithNs,
    deleteByUuid: mocks.endpointDelete,
  },
  namespacesRepository: { findByUuid: mocks.nsFind },
  mcpServersRepository: { create: mocks.serverCreate },
  ApiKeysRepository: class {
    create = mocks.keyCreate;
    deleteByName = mocks.keyDeleteByName;
  },
}));
vi.mock("../lib/authz", () => ({
  canMutate: async (owner: string | null, user: string) => owner === user,
  denyMessage: (_o: unknown, fallback: string) => fallback,
}));
vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), error: vi.fn(), warn: vi.fn(), debug: vi.fn() },
}));

import { endpointsImplementations as impl } from "./endpoints.impl";

const ep = (uuid: string) => ({
  uuid,
  name: "foo",
  created_at: new Date(),
  updated_at: new Date(),
  user_id: "u1",
});

const NS = "22222222-2222-4222-8222-222222222222";
const input = {
  name: "foo",
  namespaceUuid: NS,
  enableApiKeyAuth: true,
  enableClientMaxRate: false,
  enableMaxRate: false,
  enableOauth: false,
  useQueryParamAuth: false,
  enableMetamcpAdminTools: false,
  createMcpServer: true,
};

beforeEach(() => {
  vi.clearAllMocks();
  process.env.APP_URL = "http://localhost:12008";
  mocks.endpointFindByName.mockResolvedValue(undefined);
  mocks.nsFind.mockResolvedValue({ uuid: NS, name: "ns", user_id: "u1" });
  mocks.keyCreate.mockResolvedValue({ uuid: "k", key: "sk_mt_secret" });
  mocks.serverCreate.mockResolvedValue({ uuid: "s" });
  mocks.keyDeleteByName.mockResolvedValue(undefined);
});

describe("auto-generated key of an endpoint's MCP server", () => {
  it("is named after the endpoint uuid, so re-creating an endpoint name never collides", async () => {
    mocks.endpointCreate.mockResolvedValueOnce(ep("ep-1"));
    mocks.endpointCreate.mockResolvedValueOnce(ep("ep-2"));
    await impl.create(input as never, "u1");
    await impl.create(input as never, "u1");

    const names = mocks.keyCreate.mock.calls.map((c) => c[0].name);
    expect(names).toEqual([
      "Auto-generated for endpoint ep-1",
      "Auto-generated for endpoint ep-2",
    ]);
    expect(mocks.serverCreate.mock.calls[0][0].bearerToken).toBe(
      "sk_mt_secret",
    );
  });

  it("is removed again when the MCP server cannot be created", async () => {
    mocks.endpointCreate.mockResolvedValue(ep("ep-1"));
    mocks.serverCreate.mockRejectedValue(new Error("duplicate"));
    const r = await impl.create(input as never, "u1");

    expect(r, JSON.stringify(r)).toMatchObject({ success: true }); // endpoint creation itself still succeeds
    expect(mocks.keyDeleteByName).toHaveBeenCalledWith(
      "Auto-generated for endpoint ep-1",
    );
  });

  it("is removed when the endpoint is deleted", async () => {
    mocks.endpointFindWithNs.mockResolvedValue({ uuid: "ep-1", user_id: "u1" });
    mocks.endpointDelete.mockResolvedValue(ep("ep-1"));
    const r = await impl.delete({ uuid: "ep-1" }, "u1");

    expect(r.success).toBe(true);
    expect(mocks.keyDeleteByName).toHaveBeenCalledWith(
      "Auto-generated for endpoint ep-1",
    );
  });

  it("is not created when API key auth is off", async () => {
    mocks.endpointCreate.mockResolvedValue(ep("ep-1"));
    await impl.create({ ...input, enableApiKeyAuth: false } as never, "u1");
    expect(mocks.keyCreate).not.toHaveBeenCalled();
  });
});
