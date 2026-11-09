import { mcpServersRepository } from "../../db/repositories";
import { outboundPolicyForUser } from "../authz";
import { createGuardedFetch, type OutboundPolicy } from "../ssrf-guard";

// The policy is re-evaluated at connect time from the server's *owner*, so a
// non-admin cannot keep a server pointing at a private address after saving it
// with a public one (for example by flipping a DNS record). Shared servers
// (no owner) can only be created by administrators and may use internal
// addresses; a deleted/unknown server gets the strictest policy.
const TTL_MS = 30_000;
const cache = new Map<string, { allowPrivate: boolean; expires: number }>();

export function outboundPolicyForServer(
  serverUuid: string,
): () => Promise<OutboundPolicy> {
  return async () => {
    const hit = cache.get(serverUuid);
    if (hit && hit.expires > Date.now())
      return { allowPrivate: hit.allowPrivate };

    const server = await mcpServersRepository.findByUuid(serverUuid);
    const allowPrivate = !server
      ? false
      : server.user_id === null
        ? true
        : (await outboundPolicyForUser(server.user_id)).allowPrivate;
    cache.set(serverUuid, { allowPrivate, expires: Date.now() + TTL_MS });
    return { allowPrivate };
  };
}

/** A guarded fetch for everything the backend sends to this MCP server's upstream. */
export const upstreamFetchFor = (serverUuid: string) =>
  createGuardedFetch(outboundPolicyForServer(serverUuid));

export const clearUpstreamPolicyCache = () => cache.clear();
