import { describe, expect, it } from "vitest";

import {
  hashClientSecretForStorage,
  safeEqual,
  sha256Hex,
  verifyStoredClientSecret,
} from "./secret-hash";

describe("secret hashing", () => {
  it("sha256Hex matches the known vector", () => {
    expect(sha256Hex("abc")).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  it("safeEqual compares by value and length", () => {
    expect(safeEqual("abc", "abc")).toBe(true);
    expect(safeEqual("abc", "abd")).toBe(false);
    expect(safeEqual("abc", "abcd")).toBe(false);
  });

  it("stores client secrets hashed and verifies them", () => {
    const stored = hashClientSecretForStorage("mcp_secret_x");
    expect(stored).toMatch(/^sha256\$[0-9a-f]{64}$/);
    expect(stored).not.toContain("mcp_secret_x");
    expect(verifyStoredClientSecret("mcp_secret_x", stored)).toBe(true);
    expect(verifyStoredClientSecret("mcp_secret_y", stored)).toBe(false);
  });

  it("still accepts secrets registered before hashing (plaintext rows)", () => {
    expect(verifyStoredClientSecret("legacy", "legacy")).toBe(true);
    expect(verifyStoredClientSecret("other", "legacy")).toBe(false);
  });

  it("rejects missing values", () => {
    expect(verifyStoredClientSecret(undefined, "x")).toBe(false);
    expect(verifyStoredClientSecret("x", null)).toBe(false);
    expect(verifyStoredClientSecret("", "")).toBe(false);
  });

  it("a stored hash is not accepted as the secret itself", () => {
    const stored = hashClientSecretForStorage("s3cret");
    expect(verifyStoredClientSecret(stored, stored)).toBe(false);
  });
});
