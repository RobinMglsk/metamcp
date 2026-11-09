import { lookup as dnsLookup } from "node:dns";
import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

import type { FetchLike } from "@modelcontextprotocol/sdk/shared/transport.js";
import { Agent, fetch as undiciFetch } from "undici";

import {
  isLinkLocalOrMetadataAddress,
  isPrivateOrLocalHost,
} from "./host-ranges";

export class OutboundUrlError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "OutboundUrlError";
  }
}

export interface OutboundPolicy {
  /**
   * Allow loopback / private-network targets (internal MCP servers). Link-local
   * and cloud-metadata addresses are refused regardless of this flag.
   */
  allowPrivate: boolean;
}

/** A policy, or a function that resolves it per request (e.g. from the server owner's role). */
export type PolicyLike = OutboundPolicy | (() => Promise<OutboundPolicy>);

const resolvePolicy = (p: PolicyLike): Promise<OutboundPolicy> =>
  typeof p === "function" ? p() : Promise.resolve(p);

const METADATA_HOSTNAMES = new Set([
  "metadata",
  "metadata.google.internal",
  "instance-data",
  "instance-data.ec2.internal",
]);

/**
 * Callers who may not target private networks get one generic message, so the
 * checks cannot be used as an oracle for internal DNS names or address space.
 * Administrators (allowPrivate) get the specific reason.
 */
function refuse(policy: OutboundPolicy, specific: string): OutboundUrlError {
  return new OutboundUrlError(
    policy.allowPrivate ? specific : "The URL is not allowed",
  );
}

export type Resolver = (hostname: string) => Promise<string[]>;

const defaultResolver: Resolver = async (hostname) =>
  (await lookup(hostname, { all: true })).map((r) => r.address);

/** Why an address is refused under the policy, or null when it is allowed. */
function addressViolation(
  address: string,
  policy: OutboundPolicy,
): string | null {
  if (isLinkLocalOrMetadataAddress(address)) {
    return "The URL points at a link-local or cloud metadata address";
  }
  if (!policy.allowPrivate && isPrivateOrLocalHost(address)) {
    return "The URL points at a local or private network address";
  }
  return null;
}

/**
 * Validates a URL the server is about to contact on behalf of a user:
 * http(s) only, no embedded credentials, and every address the hostname
 * resolves to must be allowed by the policy.
 */
export async function assertOutboundUrlAllowed(
  rawUrl: string,
  policy: OutboundPolicy,
  resolve: Resolver = defaultResolver,
): Promise<URL> {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw refuse(policy, "Invalid URL");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw refuse(policy, "Only http and https URLs are allowed");
  }
  if (url.username || url.password) {
    throw refuse(policy, "URLs with embedded credentials are not allowed");
  }

  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (METADATA_HOSTNAMES.has(host)) {
    throw refuse(policy, "The URL points at a cloud metadata service");
  }

  let addresses: string[];
  if (isIP(host)) {
    addresses = [host];
  } else {
    if (!policy.allowPrivate && isPrivateOrLocalHost(host)) {
      throw refuse(
        policy,
        "The URL points at a local or private network address",
      );
    }
    try {
      addresses = await resolve(host);
    } catch {
      throw refuse(policy, `The host "${host}" could not be resolved`);
    }
  }

  for (const address of addresses) {
    const violation = addressViolation(address, policy);
    if (violation) throw refuse(policy, violation);
  }
  return url;
}

// ---------------------------------------------------------------------------
// Connection pinning
//
// Checking the DNS answer before connecting leaves a window in which a hostile
// DNS server can answer differently for the real connection (rebinding). The
// agents below validate the address that is actually dialled, inside the
// socket's own lookup, so the checked address is the one that is used.

type LookupCallback = (
  err: Error | null,
  address?: string | { address: string; family: number }[],
  family?: number,
) => void;

function makeAgent(policy: OutboundPolicy): Agent {
  return new Agent({
    connect: {
      lookup: ((
        hostname: string,
        options: { all?: boolean },
        callback: LookupCallback,
      ) => {
        dnsLookup(hostname, { ...options, all: true }, (err, addresses) => {
          if (err) return callback(err);
          for (const { address } of addresses) {
            const violation = addressViolation(address, policy);
            if (violation) return callback(refuse(policy, violation));
          }
          if (options.all) return callback(null, addresses);
          callback(null, addresses[0].address, addresses[0].family);
        });
      }) as never,
    },
  });
}

const agents = new Map<boolean, Agent>();
const agentFor = (policy: OutboundPolicy): Agent => {
  let agent = agents.get(policy.allowPrivate);
  if (!agent) {
    agent = makeAgent({ allowPrivate: policy.allowPrivate });
    agents.set(policy.allowPrivate, agent);
  }
  return agent;
};

/** Fetch whose connection is pinned to addresses the policy allows. */
export const createPinnedFetch =
  (policy: OutboundPolicy): FetchLike =>
  (url, init) =>
    undiciFetch(url, {
      ...(init as object),
      dispatcher: agentFor(policy),
    } as never) as unknown as Promise<Response>;

// ---------------------------------------------------------------------------

const MAX_REDIRECTS = 5;

// Headers that may accompany a redirect to another origin: nothing that
// identifies the caller (no Authorization, cookies, API keys, custom headers).
const CROSS_ORIGIN_SAFE_HEADERS = new Set([
  "accept",
  "accept-language",
  "user-agent",
]);

function stripForCrossOrigin(headers: RequestInit["headers"]): Headers {
  const safe = new Headers();
  new Headers(headers).forEach((value, name) => {
    if (CROSS_ORIGIN_SAFE_HEADERS.has(name.toLowerCase()))
      safe.set(name, value);
  });
  return safe;
}

/**
 * A fetch that re-validates the target on every request and follows redirects
 * itself, so a redirect (or a hostname that resolves to a forbidden address)
 * cannot be used to reach an address the policy refuses.
 *
 * - The connection is pinned: the address that is dialled is the one that was
 *   validated (see the agents above), which closes the DNS-rebinding gap. A
 *   custom `baseFetch` (tests) bypasses the pinning.
 * - Redirects to another origin drop every caller-supplied header (bearer
 *   tokens, API keys, cookies, ...), and are refused for requests with a body
 *   (for example the OAuth token POST carrying a client secret).
 */
export function createGuardedFetch(
  policyLike: PolicyLike,
  baseFetch?: FetchLike,
  resolve: Resolver = defaultResolver,
): FetchLike {
  return async (input, init) => {
    const policy = await resolvePolicy(policyLike);
    const send = baseFetch ?? createPinnedFetch(policy);
    let current = typeof input === "string" ? input : input.toString();
    let options: RequestInit | undefined = init;

    for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
      await assertOutboundUrlAllowed(current, policy, resolve);
      const response = await send(current, { ...options, redirect: "manual" });

      const location = response.headers.get("location");
      if (response.status < 300 || response.status >= 400 || !location) {
        return response;
      }
      if (response.status === 304) return response;

      const next = new URL(location, current);
      // Per fetch semantics 301/302/303 turn the request into a GET
      if (
        response.status === 303 ||
        ((response.status === 301 || response.status === 302) &&
          options?.method &&
          options.method.toUpperCase() === "POST")
      ) {
        options = { ...options, method: "GET", body: undefined };
      }

      if (next.origin !== new URL(current).origin) {
        // A body (possibly a one-shot stream) must not be replayed to another
        // origin: it may carry credentials, and streams cannot be replayed.
        if (options?.body !== undefined && options?.body !== null) {
          throw refuse(
            policy,
            "Redirects to another origin are not followed for requests with a body",
          );
        }
        options = {
          ...options,
          headers: stripForCrossOrigin(options?.headers),
        };
      } else if (options?.body instanceof ReadableStream) {
        // 307/308 within the origin would need the body again; a stream is consumed
        throw refuse(
          policy,
          "Cannot follow a redirect for a streamed request body",
        );
      }
      current = next.toString();
    }
    throw refuse(policy, "Too many redirects");
  };
}
