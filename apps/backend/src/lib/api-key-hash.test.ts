import { describe, expect, it } from "vitest";

import {
  API_KEY_PREFIX_LENGTH,
  apiKeyPrefix,
  hashApiKey,
} from "./api-key-hash";

describe("api key hashing", () => {
  it("is deterministic, hex and does not contain the key", () => {
    const key = "sk_mt_" + "a".repeat(64);
    const h = hashApiKey(key);
    expect(h).toMatch(/^[0-9a-f]{64}$/);
    expect(hashApiKey(key)).toBe(h);
    expect(h).not.toContain("aaaa");
  });

  it("matches the SQL used by the migration (sha256 hex of the utf8 bytes)", () => {
    // select encode(sha256(convert_to('abc','UTF8')),'hex')
    expect(hashApiKey("abc")).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  it("different keys hash differently", () => {
    expect(hashApiKey("sk_mt_a")).not.toBe(hashApiKey("sk_mt_b"));
  });

  it("prefix keeps only the leading characters", () => {
    expect(apiKeyPrefix("sk_mt_ABCDEFGH" + "x".repeat(50))).toBe(
      "sk_mt_ABCDEF",
    );
    expect(apiKeyPrefix("sk_mt_ABCDEFGH").length).toBe(API_KEY_PREFIX_LENGTH);
  });

  it("takes the prefix by code point, never splitting a surrogate pair", () => {
    const key = "😀😀😀😀😀😀😀😀😀😀😀😀😀😀";
    expect(Array.from(apiKeyPrefix(key))).toHaveLength(API_KEY_PREFIX_LENGTH);
    expect(apiKeyPrefix(key)).toBe("😀".repeat(API_KEY_PREFIX_LENGTH));
    expect(() => encodeURIComponent(apiKeyPrefix(key))).not.toThrow();
  });
});
