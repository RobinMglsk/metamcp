import express from "express";

import { auth } from "./auth";
import { hasValidSession } from "./lib/session-check";
import { initializeIdleServers, initializeOnStartup } from "./lib/startup";
import {
  createJsonBodyParser,
  resolveTrpcLimit,
} from "./middleware/body-limits.middleware";
import mcpProxyRouter from "./routers/mcp-proxy";
import oauthRouter from "./routers/oauth";
import publicEndpointsRouter from "./routers/public-metamcp";
import trpcRouter from "./routers/trpc";
import logger from "./utils/logger";

const app = express();

// Which proxies' X-Forwarded-For to believe when deriving the client IP used by
// the per-IP rate limiters. Default: none (req.ip is the socket peer). The
// bundled Next.js rewrite proxy does NOT add the real client address, and any
// X-Forwarded-For it receives is client-controlled, so trusting it by default
// would let anyone dodge per-IP limits by changing the header. When a reverse
// proxy such as nginx (which appends the real address) runs in front, set
// TRUST_PROXY (e.g. "loopback", "1", "10.0.0.0/8") to match that topology.
const trustProxy = process.env.TRUST_PROXY ?? "false";
app.set(
  "trust proxy",
  trustProxy === "true"
    ? true
    : trustProxy === "false"
      ? false
      : /^\d+$/.test(trustProxy)
        ? Number(trustProxy)
        : trustProxy,
);

// Global JSON middleware for non-proxy routes: small default limit, larger
// limit for tRPC only after the session was checked (see body-limits).
// MCP proxy routes and public endpoints skip parsing to allow raw stream access.
app.use(
  createJsonBodyParser({
    hasValidSession,
    trpcLimitBytes: resolveTrpcLimit(process.env.MAX_TRPC_BODY_BYTES),
  }),
);

// Mount OAuth metadata endpoints at root level for .well-known discovery
app.use(oauthRouter);

// Mount better-auth routes by calling auth API directly
app.use(async (req, res, next) => {
  if (req.path.startsWith("/api/auth")) {
    try {
      // Create a web Request object from Express request
      const url = new URL(req.url, `http://${req.headers.host}`);
      // Legacy generic-OAuth callback path (better-auth <1.7), still registered
      // as redirect URI at identity providers; see redirectURI in auth.ts.
      url.pathname = url.pathname.replace(
        /^\/api\/auth\/oauth2\/callback\//,
        "/api/auth/callback/",
      );
      const headers = new Headers();

      // Copy headers from Express request
      Object.entries(req.headers).forEach(([key, value]) => {
        if (value) {
          headers.set(key, Array.isArray(value) ? value[0] : value);
        }
      });

      // Better Auth derives the client IP (rate limiting, session metadata)
      // from X-Forwarded-For and would take the left-most, client-controlled
      // entry. Replace it with the address Express resolved from its trusted
      // proxies so the header cannot be used to dodge per-IP limits.
      const clientIp = req.ip ?? req.socket.remoteAddress;
      if (clientIp) headers.set("x-forwarded-for", clientIp);
      else headers.delete("x-forwarded-for");

      // Create Request object
      const request = new Request(url.toString(), {
        method: req.method,
        headers,
        body:
          req.method !== "GET" && req.method !== "HEAD"
            ? JSON.stringify(req.body)
            : undefined,
      });

      // Call better-auth directly
      const response = await auth.handler(request);

      // Convert Response back to Express response
      res.status(response.status);

      // Copy headers
      response.headers.forEach((value, key) => {
        res.setHeader(key, value);
      });

      // Send body
      const body = await response.text();
      res.send(body);
    } catch (error) {
      logger.error("Auth route error:", error);
      // Details stay in the log; the client only gets a generic error
      res.status(500).json({ error: "Internal server error" });
    }
    return;
  }
  next();
});

// Mount public endpoints routes (must be before JSON middleware to handle raw streams)
app.use("/metamcp", publicEndpointsRouter);

// Mount MCP proxy routes
app.use("/mcp-proxy", mcpProxyRouter);

// Mount tRPC routes
app.use("/trpc", trpcRouter);

async function start(): Promise<void> {
  // Startup initialization (must run after DB is reachable/migrations are applied, and before listening)
  await initializeOnStartup();

  app.listen(12009, async () => {
    console.log(`Server is running on port 12009`);
    console.log(`Auth routes available at: http://localhost:12009/api/auth`);
    console.log(
      `Public MetaMCP endpoints available at: http://localhost:12009/metamcp`,
    );
    console.log(
      `MCP Proxy routes available at: http://localhost:12009/mcp-proxy`,
    );
    console.log(`tRPC routes available at: http://localhost:12009/trpc`);

    // Wait a moment for the server to be fully ready to handle incoming connections,
    // then initialize idle servers (prevents connection errors when MCP servers connect back)
    console.log(
      "Waiting for server to be fully ready before initializing idle servers...",
    );
    await new Promise((resolve) => setTimeout(resolve, 3000)).then(
      initializeIdleServers,
    );
  });
}

start().catch((err) => {
  console.error("❌ Fatal startup error:", err);
  // Do not throw - keep consistent with other startup behavior
});

// Graceful shutdown: clean up MCP server pools on SIGTERM/SIGINT
// Prevents orphaned STDIO child processes when backend restarts
const gracefulShutdown = async (signal: string) => {
  console.log(`${signal} received, cleaning up MCP server pools...`);
  try {
    const { mcpServerPool } = await import("./lib/metamcp");
    const { metaMcpServerPool } =
      await import("./lib/metamcp/metamcp-server-pool");
    await Promise.allSettled([
      mcpServerPool.cleanupAll(),
      metaMcpServerPool.cleanupAll(),
    ]);
    console.log("MCP server pools cleaned up successfully");
  } catch (error) {
    console.error("Error during graceful shutdown:", error);
  }
  // eslint-disable-next-line no-process-exit -- intentional: terminate the process after async cleanup in the shutdown signal handler
  process.exit(0);
};

process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
process.on("SIGINT", () => gracefulShutdown("SIGINT"));

app.get("/health", (req, res) => {
  res.json({
    status: "ok",
  });
});
