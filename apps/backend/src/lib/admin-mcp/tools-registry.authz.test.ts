import { beforeEach, describe, expect, it, vi } from "vitest";

const { isAdmin, setSignup, listServers, getLogs } = vi.hoisted(() => ({
  isAdmin: vi.fn(),
  setSignup: vi.fn().mockResolvedValue({ success: true }),
  listServers: vi.fn().mockResolvedValue({ success: true, data: [] }),
  getLogs: vi.fn().mockResolvedValue({ success: true, data: [] }),
}));

vi.mock("../authz", () => ({ isAdmin }));
vi.mock("../../trpc/config.impl", () => ({
  configImplementations: new Proxy(
    { setSignupDisabled: setSignup },
    { get: (t, k) => (t as Record<string | symbol, unknown>)[k] ?? vi.fn() },
  ),
}));
vi.mock("../../trpc/logs.impl", () => ({
  logsImplementations: { getLogs, clearLogs: vi.fn() },
}));
vi.mock("../../trpc/mcp-servers.impl", () => ({
  mcpServersImplementations: { list: listServers },
}));
vi.mock("../../trpc/api-keys.impl", () => ({ apiKeysImplementations: {} }));
vi.mock("../../trpc/endpoints.impl", () => ({ endpointsImplementations: {} }));
vi.mock("../../trpc/namespaces.impl", () => ({
  namespacesImplementations: {},
}));
vi.mock("../../trpc/oauth.impl", () => ({ oauthImplementations: {} }));
vi.mock("../../trpc/tools.impl", () => ({ toolsImplementations: {} }));

import { ADMIN_TOOLS_BY_NAME } from "./tools-registry";

const tool = (name: string) => {
  const t = ADMIN_TOOLS_BY_NAME.get(name);
  if (!t) throw new Error(`missing admin tool ${name}`);
  return t;
};

beforeEach(() => vi.clearAllMocks());

describe("admin MCP tools: global settings and logs are admin-only", () => {
  it.each([
    ["metamcp_set_signup_disabled", { disabled: true }],
    ["metamcp_get_all_configs", {}],
    ["metamcp_set_config", { id: "X", value: "y" }],
    ["metamcp_get_logs", {}],
    ["metamcp_clear_logs", {}],
  ])("%s refuses non-admins", async (name, input) => {
    isAdmin.mockResolvedValue(false);
    await expect(tool(name).handler("user-1", input)).rejects.toThrow(
      /Administrator access required/,
    );
    expect(setSignup).not.toHaveBeenCalled();
    expect(getLogs).not.toHaveBeenCalled();
  });

  it("allows administrators", async () => {
    isAdmin.mockResolvedValue(true);
    await tool("metamcp_set_signup_disabled").handler("admin", {
      disabled: true,
    });
    expect(setSignup).toHaveBeenCalledWith({ disabled: true });
    expect(isAdmin).toHaveBeenCalledWith("admin");
  });

  it("does not gate ordinary tools", async () => {
    isAdmin.mockResolvedValue(false);
    await tool("metamcp_list_mcp_servers").handler("user-1", {});
    expect(listServers).toHaveBeenCalledWith("user-1");
  });
});
