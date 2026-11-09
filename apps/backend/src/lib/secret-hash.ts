import { createHash, timingSafeEqual } from "crypto";

/**
 * OAuth codes, tokens and client secrets are 256 bits of randomness, so a plain
 * SHA-256 is enough to keep them from being recoverable from the database
 * while staying indexable for lookups.
 */
export function sha256Hex(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}

const CLIENT_SECRET_PREFIX = "sha256$";

/** Stored form of a client secret: `sha256$<hex>` */
export function hashClientSecretForStorage(secret: string): string {
  return CLIENT_SECRET_PREFIX + sha256Hex(secret);
}

/**
 * Constant-time check of a presented client secret against the stored value.
 * Rows registered before hashing was introduced hold the plaintext secret;
 * they are still accepted so existing clients keep working.
 */
export function verifyStoredClientSecret(
  presented: string | undefined,
  stored: string | null | undefined,
): boolean {
  if (!presented || !stored) return false;
  if (stored.startsWith(CLIENT_SECRET_PREFIX)) {
    return safeEqual(hashClientSecretForStorage(presented), stored);
  }
  return safeEqual(presented, stored);
}
