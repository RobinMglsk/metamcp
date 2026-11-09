import { afterEach, describe, expect, it } from "vitest";

import {
  isRegistrationEnabled,
  normalizeClientName,
  validateRegistrationMetadata,
} from "./registration-validation";

const ok = { redirect_uris: ["https://a.example/cb"], client_name: "App" };

describe("validateRegistrationMetadata", () => {
  it("accepts a normal payload", () => {
    expect(validateRegistrationMetadata(ok)).toBeNull();
  });

  it("rejects oversized or malformed fields", () => {
    expect(
      validateRegistrationMetadata({ ...ok, client_name: "x".repeat(101) }),
    ).toMatch(/client_name/);
    expect(
      validateRegistrationMetadata({ ...ok, client_name: { a: 1 } }),
    ).toMatch(/client_name/);
    expect(
      validateRegistrationMetadata({
        redirect_uris: Array(11).fill("https://a.example/cb"),
      }),
    ).toMatch(/at most 10/);
    expect(
      validateRegistrationMetadata({
        redirect_uris: ["https://a.example/" + "x".repeat(3000)],
      }),
    ).toMatch(/redirect_uri/);
    expect(validateRegistrationMetadata({ redirect_uris: [42] })).toMatch(
      /redirect_uri/,
    );
    expect(
      validateRegistrationMetadata({ ...ok, logo_uri: "x".repeat(3000) }),
    ).toMatch(/logo_uri/);
    expect(
      validateRegistrationMetadata({ ...ok, scope: "s".repeat(300) }),
    ).toMatch(/scope/);
    expect(validateRegistrationMetadata({ ...ok, contacts: "a@b.c" })).toMatch(
      /contacts/,
    );
    expect(
      validateRegistrationMetadata({
        ...ok,
        contacts: Array(11).fill("a@b.c"),
      }),
    ).toMatch(/contacts/);
  });
});

describe("normalizeClientName", () => {
  it("strips control characters and falls back when empty", () => {
    expect(normalizeClientName("  My\u0000 App\n ")).toBe("My App");
    expect(normalizeClientName("\u0001\u0002")).toBe("Unnamed MCP Client");
    expect(normalizeClientName(undefined)).toBe("Unnamed MCP Client");
  });
});

describe("isRegistrationEnabled", () => {
  const prev = process.env.OAUTH_REGISTRATION_ENABLED;
  afterEach(() => {
    if (prev === undefined) delete process.env.OAUTH_REGISTRATION_ENABLED;
    else process.env.OAUTH_REGISTRATION_ENABLED = prev;
  });
  it("is on by default and can be switched off", () => {
    delete process.env.OAUTH_REGISTRATION_ENABLED;
    expect(isRegistrationEnabled()).toBe(true);
    process.env.OAUTH_REGISTRATION_ENABLED = "false";
    expect(isRegistrationEnabled()).toBe(false);
  });
});
