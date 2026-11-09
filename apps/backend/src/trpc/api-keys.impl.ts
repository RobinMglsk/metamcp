import {
  CreateApiKeyRequestSchema,
  CreateApiKeyResponseSchema,
  DeleteApiKeyRequestSchema,
  DeleteApiKeyResponseSchema,
  ListApiKeysResponseSchema,
  UpdateApiKeyRequestSchema,
  UpdateApiKeyResponseSchema,
  ValidateApiKeyRequestSchema,
  ValidateApiKeyResponseSchema,
} from "@repo/zod-types";
import { z } from "zod";

import logger from "@/utils/logger";

import { ApiKeysRepository } from "../db/repositories";
import { ApiKeysSerializer } from "../db/serializers";
import { isAdmin, OWNER_ADMIN_ONLY_MESSAGE, resolveOwner } from "../lib/authz";
import {
  isReservedKeyName,
  RESERVED_KEY_NAME_MESSAGE,
} from "../lib/reserved-key-names";

const apiKeysRepository = new ApiKeysRepository();

export const apiKeysImplementations = {
  create: async (
    input: z.infer<typeof CreateApiKeyRequestSchema>,
    userId: string,
  ): Promise<z.infer<typeof CreateApiKeyResponseSchema>> => {
    try {
      if (isReservedKeyName(input.name)) {
        throw new Error(RESERVED_KEY_NAME_MESSAGE);
      }
      const owner = await resolveOwner(input.user_id, userId, userId);
      if (!owner.ok) throw new Error(OWNER_ADMIN_ONLY_MESSAGE);
      const apiKeyUserId = owner.ownerId;

      const result = await apiKeysRepository.create({
        name: input.name,
        user_id: apiKeyUserId,
        is_active: true,
      });

      return ApiKeysSerializer.serializeCreateApiKeyResponse(result);
    } catch (error) {
      logger.error("Error creating API key:", error);
      throw new Error(
        error instanceof Error ? error.message : "Internal server error",
      );
    }
  },

  list: async (
    userId: string,
  ): Promise<z.infer<typeof ListApiKeysResponseSchema>> => {
    try {
      const apiKeys = await apiKeysRepository.findAccessibleToUser(userId);

      // Shared (user_id = null) keys are usable by everyone but their secret is
      // only shown to administrators.
      const viewerIsAdmin = await isAdmin(userId);
      const visible = apiKeys.map((k) =>
        k.user_id === null && !viewerIsAdmin
          ? { ...k, key: `${k.key.slice(0, 12)}…` }
          : k,
      );

      return {
        apiKeys: ApiKeysSerializer.serializeApiKeyList(visible),
      };
    } catch (error) {
      logger.error("Error fetching API keys:", error);
      throw new Error("Failed to fetch API keys");
    }
  },

  update: async (
    input: z.infer<typeof UpdateApiKeyRequestSchema>,
    userId: string,
  ): Promise<z.infer<typeof UpdateApiKeyResponseSchema>> => {
    try {
      if (input.name && isReservedKeyName(input.name)) {
        throw new Error(RESERVED_KEY_NAME_MESSAGE);
      }
      const result = await apiKeysRepository.update(
        input.uuid,
        userId,
        { name: input.name, is_active: input.is_active },
        await isAdmin(userId),
      );

      return ApiKeysSerializer.serializeApiKey(result);
    } catch (error) {
      logger.error("Error updating API key:", error);
      throw new Error(
        error instanceof Error ? error.message : "Internal server error",
      );
    }
  },

  delete: async (
    input: z.infer<typeof DeleteApiKeyRequestSchema>,
    userId: string,
  ): Promise<z.infer<typeof DeleteApiKeyResponseSchema>> => {
    try {
      await apiKeysRepository.delete(input.uuid, userId, await isAdmin(userId));

      return {
        success: true,
        message: "API key deleted successfully",
      };
    } catch (error) {
      logger.error("Error deleting API key:", error);
      return {
        success: false,
        message:
          error instanceof Error ? error.message : "Internal server error",
      };
    }
  },

  validate: async (
    input: z.infer<typeof ValidateApiKeyRequestSchema>,
  ): Promise<z.infer<typeof ValidateApiKeyResponseSchema>> => {
    try {
      const result = await apiKeysRepository.validateApiKey(input.key);
      return {
        valid: result.valid,
        user_id: result.user_id ?? undefined,
        key_uuid: result.key_uuid,
      };
    } catch (error) {
      logger.error("Error validating API key:", error);
      return { valid: false };
    }
  },
};
