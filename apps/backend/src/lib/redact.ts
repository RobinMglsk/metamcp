export const REDACTED = "[hidden]";

export interface SecretFields {
  env: Record<string, string> | null | undefined;
  bearerToken: string | null | undefined;
  headers: Record<string, string> | null | undefined;
  url?: string | null | undefined;
  args?: string[] | null | undefined;
}

// Query strings and userinfo of URLs often carry tokens (?api_key=..., user:pass@)
function maskUrl(url: string): string {
  try {
    const u = new URL(url);
    if (!u.username && !u.password && !u.search) return url;
    u.username = "";
    u.password = "";
    const query = u.search ? `?${REDACTED}` : "";
    return `${u.origin}${u.pathname}${query}${u.hash}`;
  } catch {
    return url.replace(/\?.*$/, `?${REDACTED}`);
  }
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
    // Command-line arguments commonly carry tokens (--api-key X, --token=...)
    args: server.args ? server.args.map(() => REDACTED) : server.args,
    url: server.url ? maskUrl(server.url) : server.url,
  };
}
