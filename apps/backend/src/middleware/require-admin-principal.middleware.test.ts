import { beforeEach, describe, expect, it, vi } from "vitest";

const { isAdmin } = vi.hoisted(() => ({ isAdmin: vi.fn() }));
vi.mock("../lib/authz", () => ({ isAdmin }));
vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), error: vi.fn(), warn: vi.fn(), debug: vi.fn() },
}));

import { requireAdminPrincipal } from "./require-admin-principal.middleware";

const run = async (req: Record<string, unknown>) => {
  const res = {
    status: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
  };
  const next = vi.fn();
  await requireAdminPrincipal(req as never, res as never, next);
  return { res, next };
};

beforeEach(() => isAdmin.mockReset());

describe("requireAdminPrincipal", () => {
  it("refuses unauthenticated callers (endpoint without auth)", async () => {
    isAdmin.mockResolvedValue(false);
    const { res, next } = await run({});
    expect(isAdmin).toHaveBeenCalledWith(undefined);
    expect(res.status).toHaveBeenCalledWith(403);
    expect(next).not.toHaveBeenCalled();
  });

  it("refuses non-admin API key owners and public keys", async () => {
    isAdmin.mockResolvedValue(false);
    expect((await run({ apiKeyUserId: "u2" })).res.status).toHaveBeenCalledWith(
      403,
    );
    expect(
      (await run({ apiKeyUserId: undefined })).res.status,
    ).toHaveBeenCalledWith(403);
  });

  it("allows an administrator's API key or OAuth token", async () => {
    isAdmin.mockResolvedValue(true);
    expect((await run({ apiKeyUserId: "admin" })).next).toHaveBeenCalled();
    expect(isAdmin).toHaveBeenLastCalledWith("admin");
    expect((await run({ oauthUserId: "admin2" })).next).toHaveBeenCalled();
    expect(isAdmin).toHaveBeenLastCalledWith("admin2");
  });

  it("fails closed on unexpected errors", async () => {
    const req = {
      get apiKeyUserId(): string {
        throw new Error("lookup failed");
      },
    };
    const { res, next } = await run(req);
    expect(res.status).toHaveBeenCalledWith(500);
    expect(next).not.toHaveBeenCalled();
  });
});
