import express from "express";

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
export function createJsonBodyParser({
  hasValidSession,
  trpcLimitBytes = DEFAULT_TRPC_JSON_LIMIT_BYTES,
  skipPrefixes = ["/mcp-proxy/", "/metamcp/"],
}: BodyLimitOptions): express.RequestHandler {
  const small = express.json({ limit: DEFAULT_JSON_LIMIT_BYTES });
  const large = express.json({ limit: trpcLimitBytes });

  return async (req, res, next) => {
    if (skipPrefixes.some((p) => req.path.startsWith(p))) return next();
    if (!req.path.startsWith("/trpc/")) return small(req, res, next);

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
    } catch {
      return res.status(500).json({ error: "Internal server error" });
    }
    return large(req, res, next);
  };
}
