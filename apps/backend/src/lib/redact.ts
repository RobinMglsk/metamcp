export const REDACTED = "[hidden]";

export interface SecretFields {
  env: Record<string, string> | null | undefined;
  bearerToken: string | null | undefined;
  headers: Record<string, string> | null | undefined;
}

/**
 * Connection secrets of shared servers are only visible to administrators and
 * to the owner; everyone else can use the server but not read its credentials.
 */
export function redactSecrets<T extends SecretFields>(
  server: T,
  ownerId: string | null,
  viewer: { userId: string; isAdmin: boolean },
): T {
  if (viewer.isAdmin || ownerId === viewer.userId) return server;
  const mask = (r: Record<string, string> | null | undefined) =>
    r ? Object.fromEntries(Object.keys(r).map((k) => [k, REDACTED])) : r;
  return {
    ...server,
    env: mask(server.env),
    headers: mask(server.headers),
    bearerToken: server.bearerToken ? null : server.bearerToken,
  };
}
