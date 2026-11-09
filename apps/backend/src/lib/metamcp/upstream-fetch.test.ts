import { beforeEach, describe, expect, it, vi } from "vitest";

const { findByUuid, policyForUser } = vi.hoisted(() => ({
  findByUuid: vi.fn(),
  policyForUser: vi.fn(),
}));
vi.mock("../../db/repositories", () => ({
  mcpServersRepository: { findByUuid },
}));
vi.mock("../authz", () => ({ outboundPolicyForUser: policyForUser }));

import { discoverAuthorizationServerMetadata } from "../oauth-upstream/token-exchange";
import {
  clearUpstreamPolicyCache,
  outboundPolicyForServer,
  upstreamFetchFor,
} from "./upstream-fetch";

beforeEach(() => {
  vi.clearAllMocks();
  clearUpstreamPolicyCache();
});

describe("outbound policy of an upstream server", () => {
  it("follows the owner's role, evaluated when connecting", async () => {
    findByUuid.mockResolvedValue({ uuid: "s1", user_id: "owner" });
    policyForUser.mockResolvedValue({ allowPrivate: false });
    expect(await outboundPolicyForServer("s1")()).toEqual({
      allowPrivate: false,
    });
    expect(policyForUser).toHaveBeenCalledWith("owner");
  });

  it("allows internal addresses for administrators' servers", async () => {
    findByUuid.mockResolvedValue({ uuid: "s2", user_id: "admin" });
    policyForUser.mockResolvedValue({ allowPrivate: true });
    expect(await outboundPolicyForServer("s2")()).toEqual({
      allowPrivate: true,
    });
  });

  it("allows shared servers (only administrators can create them) and refuses unknown ones", async () => {
    findByUuid.mockResolvedValueOnce({ uuid: "s3", user_id: null });
    expect(await outboundPolicyForServer("s3")()).toEqual({
      allowPrivate: true,
    });
    findByUuid.mockResolvedValueOnce(undefined);
    expect(await outboundPolicyForServer("gone")()).toEqual({
      allowPrivate: false,
    });
  });

  it("caches the answer briefly instead of querying on every request", async () => {
    findByUuid.mockResolvedValue({ uuid: "s4", user_id: "o" });
    policyForUser.mockResolvedValue({ allowPrivate: false });
    const policy = outboundPolicyForServer("s4");
    await policy();
    await policy();
    expect(findByUuid).toHaveBeenCalledTimes(1);
  });
});

describe("wiring", () => {
  it("the upstream fetch refuses metadata addresses whatever the owner", async () => {
    findByUuid.mockResolvedValue({ uuid: "s5", user_id: null });
    await expect(
      upstreamFetchFor("s5")("http://169.254.169.254/latest/meta-data/"),
    ).rejects.toThrow(/metadata|link-local/);
  });

  it("OAuth discovery without a caller-supplied fetch uses the strict default (no private targets)", async () => {
    // network-free: refused before any request is made, which discovery reports as "absent"
    expect(
      await discoverAuthorizationServerMetadata("http://10.0.0.5"),
    ).toBeNull();
    expect(
      await discoverAuthorizationServerMetadata("http://169.254.169.254"),
    ).toBeNull();
  });
});
