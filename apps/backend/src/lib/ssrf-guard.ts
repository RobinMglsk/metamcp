import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

import type { FetchLike } from "@modelcontextprotocol/sdk/shared/transport.js";

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

const METADATA_HOSTNAMES = new Set([
  "metadata",
  "metadata.google.internal",
  "instance-data",
  "instance-data.ec2.internal",
]);

export type Resolver = (hostname: string) => Promise<string[]>;

const defaultResolver: Resolver = async (hostname) =>
  (await lookup(hostname, { all: true })).map((r) => r.address);

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
    throw new OutboundUrlError("Invalid URL");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new OutboundUrlError("Only http and https URLs are allowed");
  }
  if (url.username || url.password) {
    throw new OutboundUrlError(
      "URLs with embedded credentials are not allowed",
    );
  }

  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (METADATA_HOSTNAMES.has(host)) {
    throw new OutboundUrlError("The URL points at a cloud metadata service");
  }

  let addresses: string[];
  if (isIP(host)) {
    addresses = [host];
  } else {
    if (!policy.allowPrivate && isPrivateOrLocalHost(host)) {
      throw new OutboundUrlError(
        "The URL points at a local or private network address",
      );
    }
    try {
      addresses = await resolve(host);
    } catch {
      throw new OutboundUrlError(`The host "${host}" could not be resolved`);
    }
  }

  for (const address of addresses) {
    if (isLinkLocalOrMetadataAddress(address)) {
      throw new OutboundUrlError(
        "The URL points at a link-local or cloud metadata address",
      );
    }
    if (!policy.allowPrivate && isPrivateOrLocalHost(address)) {
      throw new OutboundUrlError(
        "The URL points at a local or private network address",
      );
    }
  }
  return url;
}

const MAX_REDIRECTS = 5;

/**
 * A fetch that re-validates the target on every request and follows redirects
 * itself, so a redirect (or a hostname that resolves to a forbidden address)
 * cannot be used to reach an address the policy refuses.
 *
 * Note: the address is checked right before connecting, not pinned to the
 * connection, so a DNS server that answers differently the second time
 * (rebinding) is narrowed but not fully excluded.
 */
export function createGuardedFetch(
  policy: OutboundPolicy,
  baseFetch: FetchLike = (url, init) => fetch(url, init),
  resolve: Resolver = defaultResolver,
): FetchLike {
  return async (input, init) => {
    let current = typeof input === "string" ? input : input.toString();
    let options: RequestInit | undefined = init;

    for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
      await assertOutboundUrlAllowed(current, policy, resolve);
      const response = await baseFetch(current, {
        ...options,
        redirect: "manual",
      });

      const location = response.headers.get("location");
      if (response.status < 300 || response.status >= 400 || !location) {
        return response;
      }
      if (response.status === 304) return response;

      current = new URL(location, current).toString();
      // Per fetch semantics 301/302/303 turn the request into a GET
      if (
        response.status === 303 ||
        ((response.status === 301 || response.status === 302) &&
          options?.method &&
          options.method.toUpperCase() === "POST")
      ) {
        options = { ...options, method: "GET", body: undefined };
      }
    }
    throw new OutboundUrlError("Too many redirects");
  };
}
