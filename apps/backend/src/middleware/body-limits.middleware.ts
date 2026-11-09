import express from "express";

import logger from "@/utils/logger";

/** Bodies up to this size are accepted from anyone on any route. */
export const DEFAULT_JSON_LIMIT_BYTES = 100 * 1024;
/** Larger tRPC bodies (bulk imports, big tool schemas) need a signed-in user. */
export const DEFAULT_TRPC_JSON_LIMIT_BYTES = 10 * 1024 * 1024;

export interface BodyLimitOptions {
  /** Tells whether the request carries a valid session (checked only for large tRPC bodies). */
  hasValidSession: (req: express.Request) => Promise<boolean>;
  trpcLimitBytes?: number;
  /** Paths that must keep their raw stream (MCP proxy / public endpoints). */
  skipPrefixes?: string[];
}

/**
 * JSON body parsing with size limits that match who is allowed to send what:
 * a small default for everything (so unauthenticated requests cannot make the
 * server buffer tens of megabytes), and a larger one for tRPC only after a
 * session was verified. Replaces a blanket 50 MB limit applied before
 * authentication.
 */
/**
 * Resolves MAX_TRPC_BODY_BYTES: a positive integer not below the default limit
 * for everyone, otherwise the default (a smaller or invalid value would make
 * the "large" limit stricter than the small one, or reject every body).
 */
export function resolveTrpcLimit(raw: string | undefined): number {
  if (raw === undefined || raw.trim() === "") {
    return DEFAULT_TRPC_JSON_LIMIT_BYTES;
  }
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed < DEFAULT_JSON_LIMIT_BYTES) {
    logger.warn(
      `Ignoring MAX_TRPC_BODY_BYTES="${raw}": it must be an integer of at least ${DEFAULT_JSON_LIMIT_BYTES}; using ${DEFAULT_TRPC_JSON_LIMIT_BYTES}`,
    );
    return DEFAULT_TRPC_JSON_LIMIT_BYTES;
  }
  return parsed;
}

/** A request carries a body when it declares a length or a transfer encoding. */
function hasBody(req: express.Request): boolean {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return false;
  const length = req.headers["content-length"];
  return (
    req.headers["transfer-encoding"] !== undefined ||
    (length !== undefined && Number(length) > 0)
  );
}

export function createJsonBodyParser({
  hasValidSession,
  trpcLimitBytes = DEFAULT_TRPC_JSON_LIMIT_BYTES,
  skipPrefixes = ["/mcp-proxy/", "/metamcp/"],
}: BodyLimitOptions): express.RequestHandler {
  const small = express.json({ limit: DEFAULT_JSON_LIMIT_BYTES });
  const large = express.json({ limit: trpcLimitBytes });

  return async (req, res, next) => {
    // Express routes case-insensitively, so the checks must be too
    const path = req.path.toLowerCase();
    if (skipPrefixes.some((p) => path.startsWith(p))) return next();
    if (!path.startsWith("/trpc/")) return small(req, res, next);

    // Requests without a body (public queries, CORS preflights) and small
    // bodies need no session
    if (!hasBody(req)) return next();
    const declared = Number(req.headers["content-length"]);
    if (Number.isFinite(declared) && declared <= DEFAULT_JSON_LIMIT_BYTES) {
      return small(req, res, next);
    }

    // Large or unknown-length body: only for signed-in users
    try {
      if (!(await hasValidSession(req))) {
        return res.status(401).json({
          error: "unauthorized",
          message: "Authentication required for large requests",
        });
      }
    } catch (error) {
      logger.error("Body limit: session check failed:", error);
      return res.status(500).json({ error: "Internal server error" });
    }
    return large(req, res, next);
  };
}
