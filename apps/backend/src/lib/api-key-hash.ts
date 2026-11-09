import { createHash } from "crypto";

/** Number of leading characters kept (in clear) to help users tell keys apart. */
export const API_KEY_PREFIX_LENGTH = 12;

/**
 * API keys are 256 bits of randomness, so a plain SHA-256 is sufficient (no
 * salt or stretching needed) and keeps lookups indexable. Only the hash is
 * stored; the key itself is shown once, when it is created.
 */
export function hashApiKey(key: string): string {
  return createHash("sha256").update(key, "utf8").digest("hex");
}

export function apiKeyPrefix(key: string): string {
  return key.slice(0, API_KEY_PREFIX_LENGTH);
}
