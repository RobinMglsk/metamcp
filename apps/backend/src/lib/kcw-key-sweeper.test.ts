import { describe, expect, it, vi } from "vitest";

vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), error: vi.fn(), warn: vi.fn(), debug: vi.fn() },
}));
vi.mock("../db/repositories/api-keys.repo", () => ({
  ApiKeysRepository: class {},
}));

const { RETENTION_MS, sweepExpiredSessionKeys } =
  await import("./kcw-key-sweeper");

describe("sweepExpiredSessionKeys", () => {
  it("deletes keys that expired or were revoked more than a day ago", async () => {
    const repo = { deleteExpiredSessionKeys: vi.fn().mockResolvedValue(2) };
    const now = Date.UTC(2030, 0, 2);
    expect(await sweepExpiredSessionKeys(repo, now)).toBe(2);
    expect(repo.deleteExpiredSessionKeys).toHaveBeenCalledWith(
      new Date(now - RETENTION_MS),
    );
  });

  it("survives a database error", async () => {
    const repo = {
      deleteExpiredSessionKeys: vi.fn().mockRejectedValue(new Error("down")),
    };
    expect(await sweepExpiredSessionKeys(repo)).toBe(0);
  });
});
