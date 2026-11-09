const MAX_REDIRECT_URIS = 10;
const MAX_URL_LENGTH = 2048;
const MAX_NAME_LENGTH = 100;
const MAX_SHORT_FIELD = 256;
const MAX_CONTACTS = 10;

// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /[\u0000-\u001f\u007f]/g;

export function isRegistrationEnabled(): boolean {
  return process.env.OAUTH_REGISTRATION_ENABLED !== "false";
}

/**
 * Bounds the size and shape of the (unauthenticated) registration payload so
 * clients cannot store arbitrarily large or malformed metadata. Returns an
 * error description, or null when valid.
 */
export function validateRegistrationMetadata(
  body: Record<string, unknown>,
): string | null {
  const uris = body.redirect_uris;
  if (Array.isArray(uris)) {
    if (uris.length > MAX_REDIRECT_URIS) {
      return `redirect_uris may contain at most ${MAX_REDIRECT_URIS} entries`;
    }
    for (const u of uris) {
      if (typeof u !== "string" || u.length > MAX_URL_LENGTH) {
        return `each redirect_uri must be a string of at most ${MAX_URL_LENGTH} characters`;
      }
    }
  }

  const name = body.client_name;
  if (name !== undefined && name !== null) {
    if (typeof name !== "string" || name.length > MAX_NAME_LENGTH) {
      return `client_name must be a string of at most ${MAX_NAME_LENGTH} characters`;
    }
  }

  for (const field of ["client_uri", "logo_uri", "tos_uri", "policy_uri"]) {
    const v = body[field];
    if (v !== undefined && v !== null) {
      if (typeof v !== "string" || v.length > MAX_URL_LENGTH) {
        return `${field} must be a string of at most ${MAX_URL_LENGTH} characters`;
      }
    }
  }

  for (const field of ["scope", "software_id", "software_version"]) {
    const v = body[field];
    if (v !== undefined && v !== null) {
      if (typeof v !== "string" || v.length > MAX_SHORT_FIELD) {
        return `${field} must be a string of at most ${MAX_SHORT_FIELD} characters`;
      }
    }
  }

  const contacts = body.contacts;
  if (contacts !== undefined && contacts !== null) {
    if (
      !Array.isArray(contacts) ||
      contacts.length > MAX_CONTACTS ||
      contacts.some((c) => typeof c !== "string" || c.length > MAX_SHORT_FIELD)
    ) {
      return `contacts must be an array of at most ${MAX_CONTACTS} short strings`;
    }
  }

  return null;
}

/** Display name for the consent page: no control characters, trimmed. */
export function normalizeClientName(name: unknown): string {
  if (typeof name !== "string") return "Unnamed MCP Client";
  const cleaned = name.replace(CONTROL_CHARS, "").trim();
  return cleaned || "Unnamed MCP Client";
}
