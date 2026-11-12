import { afterEach, describe, expect, it, vi } from "vitest";

import {
  checkStartupConfig,
  enforceStartupConfig,
  isPlaceholderSecret,
  isWeakPassword,
} from "./config-guard";

const GOOD_SECRET = "k3Jx9mQ2vT7pLw4Zr8NcB5yHdF1sGa6E0uXoIeRtYn=";
const prod = { NODE_ENV: "production", BETTER_AUTH_SECRET: GOOD_SECRET };

describe("placeholder / weak value detection", () => {
  it.each([
    "your-super-secret-key-change-this-in-production",
    "change-me",
    "your_auth_secret",
    "short",
    "a".repeat(31),
    "this-is-an-example-secret-value-123456789",
  ])("flags secret %s", (s) => expect(isPlaceholderSecret(s)).toBe(true));

  it("accepts a generated secret", () => {
    expect(isPlaceholderSecret(GOOD_SECRET)).toBe(false);
  });

  it.each(["changeme", "Password", "m3t4mcp", "short", "admin-password"])(
    "flags password %s",
    (p) => expect(isWeakPassword(p)).toBe(true),
  );
  it("accepts a strong password", () => {
    expect(isWeakPassword("correct-horse-battery-staple-9")).toBe(false);
  });
});

describe("checkStartupConfig", () => {
  it("errors in production for a placeholder secret and weak bootstrap password", () => {
    const r = checkStartupConfig({
      NODE_ENV: "production",
      BETTER_AUTH_SECRET: "your-super-secret-key-change-this-in-production",
      BOOTSTRAP_USER_PASSWORD: "changeme",
    });
    expect(r.errors).toHaveLength(2);
  });

  it("checks passwords inside BOOTSTRAP_USERS", () => {
    const r = checkStartupConfig({
      ...prod,
      BOOTSTRAP_USERS: JSON.stringify([{ email: "a@b.c", password: "pass1" }]),
    });
    expect(r.errors).toHaveLength(1);
  });

  it("only warns outside production", () => {
    const r = checkStartupConfig({
      NODE_ENV: "development",
      BETTER_AUTH_SECRET: "change-me",
    });
    expect(r.errors).toEqual([]);
    expect(r.warnings).toHaveLength(1);
  });

  it("flags a placeholder KCW_SERVICE_TOKEN, and accepts a generated one", () => {
    const bad = checkStartupConfig({ ...prod, KCW_SERVICE_TOKEN: "change-me" });
    expect(bad.errors).toHaveLength(1);
    expect(bad.errors[0]).toContain("KCW_SERVICE_TOKEN");
    expect(
      checkStartupConfig({ ...prod, KCW_SERVICE_TOKEN: GOOD_SECRET }).errors,
    ).toEqual([]);
    expect(checkStartupConfig(prod).errors).toEqual([]);
  });

  it("is clean for a proper production config", () => {
    expect(
      checkStartupConfig({
        ...prod,
        BOOTSTRAP_USER_PASSWORD: "correct-horse-battery-staple-9",
        DATABASE_URL: "postgresql://u:Zk29-qWx8-Lm33-pPd4@db:5432/x",
      }),
    ).toEqual({ errors: [], warnings: [] });
  });

  it("warns about the default database password and unauthenticated bootstrap endpoints", () => {
    const r = checkStartupConfig({
      ...prod,
      DATABASE_URL: "postgresql://u:m3t4mcp@db:5432/x",
      BOOTSTRAP_ENDPOINTS: JSON.stringify([
        { name: "Public", enable_auth: false },
        { name: "Secure", enable_auth: true },
        { name: "Oauth", enable_auth: false, enable_auth_oauth: true },
      ]),
    });
    expect(r.errors).toEqual([]);
    expect(r.warnings).toHaveLength(2);
    expect(r.warnings.join(" ")).toContain("Public");
    expect(r.warnings.join(" ")).not.toContain("Oauth");
  });
});

describe("enforceStartupConfig", () => {
  afterEach(() => vi.restoreAllMocks());

  it("exits(1) on errors in production", () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const exit = vi
      .spyOn(process, "exit")
      .mockImplementation((() => undefined) as never);
    enforceStartupConfig({
      NODE_ENV: "production",
      BETTER_AUTH_SECRET: "change-me",
    });
    expect(exit).toHaveBeenCalledWith(1);
  });

  it("does not exit with ALLOW_INSECURE_DEFAULTS=true", () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const exit = vi
      .spyOn(process, "exit")
      .mockImplementation((() => undefined) as never);
    enforceStartupConfig({
      NODE_ENV: "production",
      BETTER_AUTH_SECRET: "change-me",
      ALLOW_INSECURE_DEFAULTS: "true",
    });
    expect(exit).not.toHaveBeenCalled();
  });

  it("does not exit for a good config", () => {
    const exit = vi
      .spyOn(process, "exit")
      .mockImplementation((() => undefined) as never);
    enforceStartupConfig(prod);
    expect(exit).not.toHaveBeenCalled();
  });
});
