import {
  CreateToolRequestSchema,
  CreateToolResponseSchema,
  GetToolsByMcpServerUuidRequestSchema,
  GetToolsByMcpServerUuidResponseSchema,
} from "@repo/zod-types";
import { z } from "zod";

import logger from "@/utils/logger";

import { mcpServersRepository, toolsRepository } from "../db/repositories";
import { ToolsSerializer } from "../db/serializers";
import { canMutate } from "../lib/authz";
import { toolsSyncCache } from "../lib/metamcp/tools-sync-cache";

// The tools of a server belong to that server: reading follows the server's
// visibility (own or shared), writing needs ownership (admin for shared).
type ServerAccess = "ok" | "not_found" | "denied";
const checkServerAccess = async (
  mcpServerUuid: string,
  userId: string,
  write: boolean,
): Promise<ServerAccess> => {
  const server = await mcpServersRepository.findByUuid(mcpServerUuid);
  if (!server) return "not_found";
  if (write) {
    return (await canMutate(server.user_id, userId)) ? "ok" : "denied";
  }
  return !server.user_id || server.user_id === userId ? "ok" : "denied";
};

const accessMessage = (access: Exclude<ServerAccess, "ok">) =>
  access === "not_found"
    ? "MCP server not found"
    : "Access denied: you do not have access to this MCP server";

export const toolsImplementations = {
  getByMcpServerUuid: async (
    input: z.infer<typeof GetToolsByMcpServerUuidRequestSchema>,
    userId: string,
  ): Promise<z.infer<typeof GetToolsByMcpServerUuidResponseSchema>> => {
    try {
      const access = await checkServerAccess(
        input.mcpServerUuid,
        userId,
        false,
      );
      if (access !== "ok") {
        return {
          success: false as const,
          data: [],
          message: accessMessage(access),
        };
      }

      const tools = await toolsRepository.findByMcpServerUuid(
        input.mcpServerUuid,
      );

      return {
        success: true as const,
        data: ToolsSerializer.serializeToolList(tools),
        message: "Tools retrieved successfully",
      };
    } catch (error) {
      logger.error("Error fetching tools by MCP server UUID:", error);
      return {
        success: false as const,
        data: [],
        message: "Failed to fetch tools",
      };
    }
  },

  create: async (
    input: z.infer<typeof CreateToolRequestSchema>,
    userId: string,
  ): Promise<z.infer<typeof CreateToolResponseSchema>> => {
    try {
      const access = await checkServerAccess(input.mcpServerUuid, userId, true);
      if (access !== "ok") {
        return {
          success: false as const,
          count: 0,
          error: accessMessage(access),
        };
      }

      if (!input.tools || input.tools.length === 0) {
        return {
          success: true as const,
          count: 0,
          message: "No tools to save",
        };
      }

      const results = await toolsRepository.bulkUpsert({
        tools: input.tools,
        mcpServerUuid: input.mcpServerUuid,
      });

      return {
        success: true as const,
        count: results.length,
        message: `Successfully saved ${results.length} tools`,
      };
    } catch (error) {
      logger.error("Error saving tools to database:", error);
      return {
        success: false as const,
        count: 0,
        error: error instanceof Error ? error.message : "Internal server error",
      };
    }
  },

  /**
   * Smart sync with hash-check and cleanup: only syncs if the tools changed.
   * Requires ownership of the server (admin for shared servers).
   */
  sync: async (
    input: z.infer<typeof CreateToolRequestSchema>,
    userId: string,
  ): Promise<z.infer<typeof CreateToolResponseSchema>> => {
    const access = await checkServerAccess(input.mcpServerUuid, userId, true);
    if (access !== "ok") {
      return {
        success: false as const,
        count: 0,
        error: accessMessage(access),
      };
    }
    return syncDiscoveredTools(input);
  },
};

/**
 * Trusted internal entry point (no per-user access check): used by the proxy
 * when it syncs tools it just discovered from a server it is connected to.
 * User-facing callers must go through `toolsImplementations.sync`.
 */
export const syncDiscoveredTools = async (
  input: z.infer<typeof CreateToolRequestSchema>,
): Promise<z.infer<typeof CreateToolResponseSchema>> => {
  try {
    if (!input.tools || input.tools.length === 0) {
      return {
        success: true as const,
        count: 0,
        message: "No tools to sync",
      };
    }

    // Check if tools changed using hash
    const toolNames = input.tools.map((tool) => tool.name);
    const hasChanged = toolsSyncCache.hasChanged(
      input.mcpServerUuid,
      toolNames,
    );

    if (hasChanged) {
      // Update cache
      toolsSyncCache.update(input.mcpServerUuid, toolNames);

      // Perform sync with cleanup
      const { upserted, deleted } = await toolsRepository.syncTools({
        tools: input.tools,
        mcpServerUuid: input.mcpServerUuid,
      });

      const message =
        deleted.length > 0
          ? `Successfully synced ${upserted.length} tools (removed ${deleted.length} obsolete)`
          : `Successfully synced ${upserted.length} tools`;

      return {
        success: true as const,
        count: upserted.length,
        message,
      };
    } else {
      return {
        success: true as const,
        count: input.tools.length,
        message: "Tools unchanged, skipped sync",
      };
    }
  } catch (error) {
    console.error("Error syncing tools to database:", error);
    return {
      success: false as const,
      count: 0,
      error: error instanceof Error ? error.message : "Internal server error",
    };
  }
};
