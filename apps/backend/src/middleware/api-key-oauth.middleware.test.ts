import type { DatabaseEndpoint } from "@repo/zod-types";
import { describe, expect, it, vi } from "vitest";

vi.mock("../db/repositories/api-keys.repo", () => ({
  ApiKeysRepository: class {},
}));
vi.mock("../lib/auth-rate-limiter", () => ({
  authRateLimiter: {},
  getAuthRateLimitIdentifier: vi.fn(),
}));

const { checkApiKeyAccess } = await import("./api-key-oauth.middleware");

const endpoint = (name: string, user_id: string | null = null) =>
  ({ name, user_id }) as DatabaseEndpoint;

describe("checkApiKeyAccess endpoint scope", () => {
  it("allows every endpoint when the key has no scope", () => {
    expect(
      checkApiKeyAccess({ user_id: null, endpoint_names: null }, endpoint("a"))
        .allowed,
    ).toBe(true);
    expect(checkApiKeyAccess({ user_id: null }, endpoint("a")).allowed).toBe(
      true,
    );
  });

  it("allows only the listed endpoints", () => {
    const key = { user_id: null, endpoint_names: ["a"] };
    expect(checkApiKeyAccess(key, endpoint("a")).allowed).toBe(true);
    const denied = checkApiKeyAccess(key, endpoint("b"));
    expect(denied.allowed).toBe(false);
    expect(denied.message).toMatch(/not valid for this endpoint/);
  });

  it("still applies the ownership rules to a scoped key", () => {
    const key = { user_id: null, endpoint_names: ["a"] };
    expect(checkApiKeyAccess(key, endpoint("a", "owner")).allowed).toBe(false);
  });
});
