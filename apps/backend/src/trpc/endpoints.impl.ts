import {
  CreateEndpointRequestSchema,
  CreateEndpointResponseSchema,
  DeleteEndpointResponseSchema,
  GetEndpointResponseSchema,
  ListEndpointsResponseSchema,
  UpdateEndpointRequestSchema,
  UpdateEndpointResponseSchema,
} from "@repo/zod-types";
import { z } from "zod";

import logger from "@/utils/logger";

import {
  ApiKeysRepository,
  endpointsRepository,
  mcpServersRepository,
  namespacesRepository,
} from "../db/repositories";
import { EndpointsSerializer } from "../db/serializers";
import { canMutate, denyMessage } from "../lib/authz";
import { autoKeyName } from "../lib/reserved-key-names";

const apiKeysRepository = new ApiKeysRepository();

export const endpointsImplementations = {
  create: async (
    input: z.infer<typeof CreateEndpointRequestSchema>,
    userId: string,
  ): Promise<z.infer<typeof CreateEndpointResponseSchema>> => {
    try {
      // Check if endpoint name already exists (must be globally unique)
      const existingEndpoint = await endpointsRepository.findByName(input.name);
      if (existingEndpoint) {
        return {
          success: false as const,
          message: "Endpoint name already exists",
        };
      }

      // Determine user ownership based on input.user_id or default to current user
      const effectiveUserId =
        input.user_id !== undefined ? input.user_id : userId;
      const isPublicEndpoint = effectiveUserId === null;

      // Validate namespace accessibility and relationship rules
      const namespace = await namespacesRepository.findByUuid(
        input.namespaceUuid,
      );
      if (!namespace) {
        return {
          success: false as const,
          message: "Selected namespace could not be found",
        };
      }

      // Check if user has access to this namespace (own namespace or public namespace)
      if (namespace.user_id && namespace.user_id !== userId) {
        return {
          success: false as const,
          message: `Access denied: You don't have permission to use namespace "${namespace.name}"`,
        };
      }

      // Enforce relationship rules: public endpoints can only use public namespaces
      if (isPublicEndpoint && namespace.user_id !== null) {
        return {
          success: false as const,
          message: `Access denied: Public endpoints can only use public namespaces. Namespace "${namespace.name}" is private`,
        };
      }

      logger.info(input);

      const result = await endpointsRepository.create({
        name: input.name,
        description: input.description,
        namespace_uuid: input.namespaceUuid,
        enable_api_key_auth: input.enableApiKeyAuth ?? true,
        enable_max_rate: input.enableMaxRate ?? false,
        enable_client_max_rate: input.enableClientMaxRate ?? false,
        max_rate: input.maxRate,
        max_rate_seconds: input.maxRateSeconds,
        client_max_rate: input.clientMaxRate,
        client_max_rate_seconds: input.clientMaxRateSeconds,
        client_max_rate_strategy: input.clientMaxRateStrategy,
        client_max_rate_strategy_key: input.clientMaxRateStrategyKey,
        enable_oauth: input.enableOauth ?? false,
        use_query_param_auth: input.useQueryParamAuth ?? false,
        enable_metamcp_admin_tools: input.enableMetamcpAdminTools ?? false,
        user_id: effectiveUserId,
      });

      // Create MCP server if requested
      if (input.createMcpServer) {
        let createdAutoKey = false;
        try {
          const mcpServerName = `${input.name}-endpoint`;
          const mcpServerDescription = `Auto-generated MCP server for endpoint "${input.name}"`;

          const baseUrl = process.env.APP_URL;
          const endpointUrl = `${baseUrl}/metamcp/${input.name}/mcp`;

          // Bearer token for the server, only if API key auth is enabled.
          // Keys are stored hashed, so an existing key cannot be reused: the
          // auto-generated MCP server gets its own dedicated key, named after
          // the endpoint's uuid (unique even when an endpoint name is reused)
          // and removed again when the endpoint is deleted.
          let bearerToken = "";
          if (input.enableApiKeyAuth) {
            try {
              const newApiKey = await apiKeysRepository.create({
                name: autoKeyName(result.uuid),
                user_id: userId,
                is_active: true,
              });
              bearerToken = newApiKey.key;
              createdAutoKey = true;
            } catch (apiKeyError) {
              logger.error(
                "Error getting API key for MCP server:",
                apiKeyError,
              );
              // Continue without bearer token if API key operation fails
            }
          }

          await mcpServersRepository.create({
            name: mcpServerName,
            description: mcpServerDescription,
            type: "STREAMABLE_HTTP",
            url: endpointUrl,
            bearerToken: bearerToken,
            command: "",
            args: [],
            env: {},
            user_id: effectiveUserId,
          });
        } catch (mcpError) {
          if (createdAutoKey) {
            // Do not leave an unused active key behind
            await apiKeysRepository
              .deleteByName(autoKeyName(result.uuid))
              .catch((e) => logger.error("Error removing unused API key:", e));
          }
          logger.error("Error creating MCP server:", mcpError);
          // Don't fail the endpoint creation if MCP server creation fails
          // Just log the error and continue
        }
      }

      return {
        success: true as const,
        data: EndpointsSerializer.serializeEndpoint(result),
        message: "Endpoint created successfully",
      };
    } catch (error) {
      logger.error("Error creating endpoint:", error);
      return {
        success: false as const,
        message:
          error instanceof Error ? error.message : "Internal server error",
      };
    }
  },

  list: async (
    userId: string,
  ): Promise<z.infer<typeof ListEndpointsResponseSchema>> => {
    try {
      // Get endpoints accessible to user (public + user's own) with namespace data
      const endpoints =
        await endpointsRepository.findAllAccessibleToUserWithNamespaces(userId);

      return {
        success: true as const,
        data: EndpointsSerializer.serializeEndpointWithNamespaceList(endpoints),
        message: "Endpoints retrieved successfully",
      };
    } catch (error) {
      logger.error("Error fetching endpoints:", error);
      return {
        success: false as const,
        data: [],
        message: "Failed to fetch endpoints",
      };
    }
  },

  get: async (
    input: {
      uuid: string;
    },
    userId: string,
  ): Promise<z.infer<typeof GetEndpointResponseSchema>> => {
    try {
      const endpoint = await endpointsRepository.findByUuidWithNamespace(
        input.uuid,
      );

      if (!endpoint) {
        return {
          success: false as const,
          message: "Endpoint not found",
        };
      }

      // Check if user has access to this endpoint (own endpoint or public endpoint)
      if (endpoint.user_id && endpoint.user_id !== userId) {
        return {
          success: false as const,
          message:
            "Access denied: You can only view endpoints you own or public endpoints",
        };
      }

      return {
        success: true as const,
        data: EndpointsSerializer.serializeEndpointWithNamespace(endpoint),
        message: "Endpoint retrieved successfully",
      };
    } catch (error) {
      logger.error("Error fetching endpoint:", error);
      return {
        success: false as const,
        message: "Failed to fetch endpoint",
      };
    }
  },

  delete: async (
    input: {
      uuid: string;
    },
    userId: string,
  ): Promise<z.infer<typeof DeleteEndpointResponseSchema>> => {
    try {
      // First, check if the endpoint exists and user has permission to delete it
      const existingEndpoint =
        await endpointsRepository.findByUuidWithNamespace(input.uuid);

      if (!existingEndpoint) {
        return {
          success: false as const,
          message: "Endpoint not found",
        };
      }

      // Check if user owns this endpoint (only owners can delete, protect public endpoints)
      if (!(await canMutate(existingEndpoint.user_id, userId))) {
        return {
          success: false as const,
          message: denyMessage(
            existingEndpoint.user_id,
            "Access denied: You can only delete endpoints you own",
          ),
        };
      }

      const deletedEndpoint = await endpointsRepository.deleteByUuid(
        input.uuid,
      );

      if (!deletedEndpoint) {
        return {
          success: false as const,
          message: "Endpoint not found",
        };
      }

      // Remove the key that was generated for this endpoint's MCP server
      await apiKeysRepository
        .deleteByName(autoKeyName(input.uuid))
        .catch((e) => logger.error("Error removing endpoint API key:", e));

      return {
        success: true as const,
        message: "Endpoint deleted successfully",
      };
    } catch (error) {
      logger.error("Error deleting endpoint:", error);
      return {
        success: false as const,
        message:
          error instanceof Error ? error.message : "Internal server error",
      };
    }
  },

  update: async (
    input: z.infer<typeof UpdateEndpointRequestSchema>,
    userId: string,
  ): Promise<z.infer<typeof UpdateEndpointResponseSchema>> => {
    try {
      // First, check if the endpoint exists and user has permission to update it
      const existingEndpoint =
        await endpointsRepository.findByUuidWithNamespace(input.uuid);

      if (!existingEndpoint) {
        return {
          success: false as const,
          message: "Endpoint not found",
        };
      }

      // Check if user owns this endpoint (only owners can update)
      if (!(await canMutate(existingEndpoint.user_id, userId))) {
        return {
          success: false as const,
          message: denyMessage(
            existingEndpoint.user_id,
            "Access denied: You can only update endpoints you own",
          ),
        };
      }

      const isPublicEndpoint = existingEndpoint.user_id === null;

      // Validate namespace accessibility and relationship rules if namespace is being updated
      if (input.namespaceUuid !== existingEndpoint.namespace_uuid) {
        const namespace = await namespacesRepository.findByUuid(
          input.namespaceUuid,
        );
        if (!namespace) {
          return {
            success: false as const,
            message: "Selected namespace could not be found",
          };
        }

        // Check if user has access to this namespace (own namespace or public namespace)
        if (namespace.user_id && namespace.user_id !== userId) {
          return {
            success: false as const,
            message: `Access denied: You don't have permission to use namespace "${namespace.name}"`,
          };
        }

        // Enforce relationship rules: public endpoints can only use public namespaces
        if (isPublicEndpoint && namespace.user_id !== null) {
          return {
            success: false as const,
            message: `Access denied: Public endpoints can only use public namespaces. Namespace "${namespace.name}" is private`,
          };
        }
      }

      // Check if another endpoint with the same name exists (excluding current one)
      const duplicateEndpoint = await endpointsRepository.findByName(
        input.name,
      );
      if (duplicateEndpoint && duplicateEndpoint.uuid !== input.uuid) {
        return {
          success: false as const,
          message: "Endpoint name already exists",
        };
      }

      const result = await endpointsRepository.update({
        uuid: input.uuid,
        name: input.name,
        description: input.description,
        namespace_uuid: input.namespaceUuid,
        enable_api_key_auth: input.enableApiKeyAuth,
        enable_max_rate: input.enableMaxRate ?? false,
        enable_client_max_rate: input.enableClientMaxRate ?? false,
        max_rate: input.maxRate,
        max_rate_seconds: input.maxRateSeconds,
        client_max_rate: input.clientMaxRate,
        client_max_rate_seconds: input.clientMaxRateSeconds,
        client_max_rate_strategy: input.clientMaxRateStrategy,
        client_max_rate_strategy_key: input.clientMaxRateStrategyKey,
        enable_oauth: input.enableOauth,
        use_query_param_auth: input.useQueryParamAuth,
        enable_metamcp_admin_tools: input.enableMetamcpAdminTools,
      });

      return {
        success: true as const,
        data: EndpointsSerializer.serializeEndpoint(result),
        message: "Endpoint updated successfully",
      };
    } catch (error) {
      logger.error("Error updating endpoint:", error);
      return {
        success: false as const,
        message:
          error instanceof Error ? error.message : "Internal server error",
      };
    }
  },
};
