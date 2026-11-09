import type express from "express";

import {
  hashClientSecretForStorage,
  verifyStoredClientSecret,
} from "../../lib/secret-hash";

export interface ClientRecord {
  client_id: string;
  client_secret?: string | null;
  token_endpoint_auth_method?: string | null;
}

export interface ClientAuthError {
  status: number;
  body: { error: string; error_description: string };
}

const invalidClient = (description: string): ClientAuthError => ({
  status: 401,
  body: { error: "invalid_client", error_description: description },
});

// RFC 6749 2.3.1: id and secret are form-urlencoded before base64. Both the
// literal and the decoded form are accepted: generated secrets contain no
// characters that encoding changes, but other clients differ in practice.
function formDecode(value: string): string {
  try {
    return decodeURIComponent(value.replace(/\+/g, " "));
  } catch {
    return value;
  }
}

function basicCredentials(
  req: express.Request,
): { id: string; secret: string }[] | null {
  const header = req.headers.authorization;
  if (!header || !header.startsWith("Basic ")) return null;
  const credentials = Buffer.from(header.substring(6), "base64").toString();
  // The id never contains ":" (it is encoded), so split on the first one
  const sep = credentials.indexOf(":");
  const id = sep === -1 ? credentials : credentials.slice(0, sep);
  const secret = sep === -1 ? "" : credentials.slice(sep + 1);
  return [
    { id, secret },
    { id: formDecode(id), secret: formDecode(secret) },
  ];
}

/**
 * Authenticates a confidential client (client_secret_basic / client_secret_post).
 * Public clients ("none") are protected by PKCE instead. Returns an error
 * response (status + body) or null when the client is authenticated.
 */
export function authenticateClient(
  req: express.Request,
  client: ClientRecord,
): ClientAuthError | null {
  const method = client.token_endpoint_auth_method;

  if (method === "client_secret_basic") {
    const candidates = basicCredentials(req);
    if (!candidates) {
      return {
        status: 401,
        body: {
          error: "invalid_client",
          error_description: "Client authentication required via Basic auth",
        },
      };
    }
    const ok = candidates.some(
      (c) =>
        c.id === client.client_id &&
        verifyStoredClientSecret(c.secret, client.client_secret),
    );
    return ok ? null : invalidClient("Invalid client credentials");
  }

  if (method === "client_secret_post") {
    return verifyStoredClientSecret(
      req.body?.client_secret,
      client.client_secret,
    )
      ? null
      : invalidClient("Invalid client secret");
  }

  return null;
}

/** The secret the client just authenticated with (basic or post), if any. */
function presentedSecret(
  req: express.Request,
  client: ClientRecord,
): string | undefined {
  if (client.token_endpoint_auth_method === "client_secret_post") {
    return req.body?.client_secret;
  }
  if (client.token_endpoint_auth_method === "client_secret_basic") {
    return basicCredentials(req)?.find(
      (c) =>
        c.id === client.client_id &&
        verifyStoredClientSecret(c.secret, client.client_secret),
    )?.secret;
  }
  return undefined;
}

/**
 * Clients registered before secrets were hashed still hold the plaintext. After
 * one successful authentication the plaintext is replaced by its hash, so such
 * rows disappear over time. Returns whether an upgrade was performed.
 */
export async function upgradeLegacySecret(
  req: express.Request,
  client: ClientRecord,
  save: (clientId: string, hashed: string) => Promise<void>,
): Promise<boolean> {
  if (!client.client_secret || client.client_secret.startsWith("sha256$")) {
    return false;
  }
  const secret = presentedSecret(req, client);
  if (!secret) return false;
  await save(client.client_id, hashClientSecretForStorage(secret));
  return true;
}
