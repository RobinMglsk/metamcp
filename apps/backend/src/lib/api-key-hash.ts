import { createHash } from "crypto";

/** Number of leading characters kept (in clear) to help users tell keys apart. */
export const API_KEY_PREFIX_LENGTH = 12;

/**
 * API keys are 256 bits of randomness, so a plain SHA-256 is sufficient (no
 * salt or stretching needed) and keeps lookups indexable. Only the hash is
 * stored; the key itself is shown once, when it is created.
 */
export function sha256Hex(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export function hashApiKey(key: string): string {
  return sha256Hex(key);
}

// By code point (not UTF-16 unit) so a prefix never splits a surrogate pair and
// matches what the migration's SQL left(key, 12) stores in a UTF-8 database.
export function apiKeyPrefix(key: string): string {
  return Array.from(key).slice(0, API_KEY_PREFIX_LENGTH).join("");
}
