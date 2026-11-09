import express from "express";

import {
  ApiKeyAuthenticatedRequest,
  authenticateApiKey,
} from "@/middleware/api-key-oauth.middleware";
import { lookupEndpoint } from "@/middleware/lookup-endpoint-middleware";
import logger from "@/utils/logger";

import {
  mcpServersRepository,
  namespacesRepository,
} from "../../db/repositories";
import { mcpServerPool } from "../../lib/metamcp/mcp-server-pool";
import { serverErrorTracker } from "../../lib/metamcp/server-error-tracker";
import { convertDbServerToParams } from "../../lib/metamcp/utils";
import { requireAdminPrincipal } from "../../middleware/require-admin-principal.middleware";

const adminRouter = express.Router();

async function respawnIdleSessions(serverUuids: string[]) {
  for (const uuid of serverUuids) {
    const server = await mcpServersRepository.findByUuid(uuid);
    if (!server) continue;
    const params = await convertDbServerToParams(server);
    if (params) {
      await mcpServerPool.ensureIdleSessionForNewServer(uuid, params);
    }
  }
}

// Only servers that belong to the endpoint's namespace may be inspected or reset
async function getNamespaceServers(req: express.Request) {
  const { endpoint } = req as ApiKeyAuthenticatedRequest;
  const namespace = await namespacesRepository.findByUuidWithServers(
    endpoint.namespace_uuid,
  );
  return namespace?.servers ?? [];
}

// JSON body parser for admin routes
adminRouter.use(express.json());

/**
 * POST /metamcp/admin/reset-errors
 *
 * Resets ERROR state for MCP servers without requiring a full backend restart.
 * Optionally targets a specific server by UUID, or resets all if no UUID given.
 *
 * Body: { "serverUuid": "optional-specific-uuid" }
 * Auth: API key (X-API-Key header) or OAuth token of an administrator
 */
adminRouter.post(
  "/:endpoint_name/admin/reset-errors",
  lookupEndpoint,
  authenticateApiKey,
  requireAdminPrincipal,
  async (req, res) => {
    try {
      const { serverUuid } = req.body || {};
      const resetResults: string[] = [];
      const resetUuids: string[] = [];

      const namespaceServers = await getNamespaceServers(req);

      if (serverUuid) {
        if (!namespaceServers.some((s) => s.uuid === serverUuid)) {
          return res.status(404).json({
            success: false,
            error: "Server not found in this endpoint's namespace",
          });
        }
        // Reset specific server
        await serverErrorTracker.resetServerErrorState(serverUuid);
        resetResults.push(serverUuid);
        resetUuids.push(serverUuid);
        logger.info(`Admin API: Reset error state for server ${serverUuid}`);
      } else {
        // Reset all servers of this namespace that are in ERROR state
        const errorServers = namespaceServers.filter(
          (s) => s.error_status === "ERROR",
        );

        for (const server of errorServers) {
          await serverErrorTracker.resetServerErrorState(server.uuid);
          resetResults.push(server.name || server.uuid);
          resetUuids.push(server.uuid);
        }

        // Also clear the in-memory crash counters of those servers
        for (const server of namespaceServers) {
          serverErrorTracker.resetServerAttempts(server.uuid);
        }

        logger.info(
          `Admin API: Reset ${resetResults.length} servers from ERROR state: ${resetResults.join(", ")}`,
        );
      }

      // Respawn idle connections for the servers that were reset (only those:
      // the global initializeIdleServers() also clears every other server's
      // error state). Run async - don't block the response.
      respawnIdleSessions(resetUuids).catch((err) => {
        logger.error("Admin API: Error re-initializing idle servers:", err);
      });

      res.json({
        success: true,
        reset: resetResults.length,
        servers: resetResults,
        message:
          resetResults.length > 0
            ? `Reset ${resetResults.length} server(s). Idle session re-initialization triggered.`
            : "No servers were in ERROR state.",
      });
    } catch (error) {
      logger.error("Admin API: Error resetting server errors:", error);
      res.status(500).json({
        success: false,
        error: "Failed to reset server errors",
        message: error instanceof Error ? error.message : String(error),
      });
    }
  },
);

/**
 * GET /metamcp/admin/error-status
 *
 * Returns current error status of the servers in the endpoint's namespace (for diagnostics).
 */
adminRouter.get(
  "/:endpoint_name/admin/error-status",
  lookupEndpoint,
  authenticateApiKey,
  requireAdminPrincipal,
  async (req, res) => {
    try {
      const allServers = await getNamespaceServers(req);
      const serverStatuses = allServers.map((s) => ({
        uuid: s.uuid,
        name: s.name,
        error_status: s.error_status,
        attempts: serverErrorTracker.getServerAttempts(s.uuid),
      }));

      const errorCount = serverStatuses.filter(
        (s) => s.error_status === "ERROR",
      ).length;

      res.json({
        timestamp: new Date().toISOString(),
        total: serverStatuses.length,
        errored: errorCount,
        servers: serverStatuses,
      });
    } catch (error) {
      logger.error("Admin API: Error fetching server statuses:", error);
      res.status(500).json({
        success: false,
        error: "Failed to fetch server statuses",
      });
    }
  },
);

export default adminRouter;
