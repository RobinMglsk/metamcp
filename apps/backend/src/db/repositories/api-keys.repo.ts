import { ApiKeyCreateInput, ApiKeyUpdateInput } from "@repo/zod-types";
import { and, desc, eq, isNull, lt, or, sql } from "drizzle-orm";
import { customAlphabet } from "nanoid";

import { apiKeyPrefix, hashApiKey } from "../../lib/api-key-hash";
import { kcwSessionKeyName } from "../../lib/reserved-key-names";
import { db } from "../index";
import { apiKeysTable } from "../schema";

const nanoid = customAlphabet(
  "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
  64,
);

// Listings never return the key or its hash: only the clear prefix followed by
// an ellipsis (empty for rows without a prefix). The field keeps the name `key`
// for API compatibility with existing clients; it is a display value only.
const displayKey = sql<string>`CASE WHEN ${apiKeysTable.key_prefix} = '' THEN '' ELSE concat(${apiKeysTable.key_prefix}, '…') END`;

export class ApiKeysRepository {
  /**
   * Generate a new API key with the specified format: sk_mt_{64-char-nanoid}
   */
  private generateApiKey(): string {
    const keyPart = nanoid();
    const key = `sk_mt_${keyPart}`;

    return key;
  }

  async create(input: ApiKeyCreateInput): Promise<{
    uuid: string;
    name: string;
    key: string;
    user_id: string | null;
    created_at: Date;
  }> {
    const key = this.generateApiKey();

    const [createdApiKey] = await db
      .insert(apiKeysTable)
      .values({
        name: input.name,
        key: hashApiKey(key),
        key_prefix: apiKeyPrefix(key),
        user_id: input.user_id,
        is_active: input.is_active ?? true,
      })
      .returning({
        uuid: apiKeysTable.uuid,
        name: apiKeysTable.name,
        user_id: apiKeysTable.user_id,
        created_at: apiKeysTable.created_at,
      });

    if (!createdApiKey) {
      throw new Error("Failed to create API key");
    }

    return {
      ...createdApiKey,
      key, // The plaintext key is only ever returned here, at creation
    };
  }

  // Find all API keys (both public and user-owned)
  async findAll() {
    return await db
      .select({
        uuid: apiKeysTable.uuid,
        name: apiKeysTable.name,
        key: displayKey,
        created_at: apiKeysTable.created_at,
        is_active: apiKeysTable.is_active,
        user_id: apiKeysTable.user_id,
      })
      .from(apiKeysTable)
      .orderBy(desc(apiKeysTable.created_at));
  }

  // Find public API keys (no user ownership)
  async findPublicApiKeys() {
    return await db
      .select({
        uuid: apiKeysTable.uuid,
        name: apiKeysTable.name,
        key: displayKey,
        created_at: apiKeysTable.created_at,
        is_active: apiKeysTable.is_active,
        user_id: apiKeysTable.user_id,
      })
      .from(apiKeysTable)
      .where(isNull(apiKeysTable.user_id))
      .orderBy(desc(apiKeysTable.created_at));
  }

  // Find API keys accessible to a specific user (public + user's own keys)
  async findAccessibleToUser(userId: string) {
    return await db
      .select({
        uuid: apiKeysTable.uuid,
        name: apiKeysTable.name,
        key: displayKey,
        created_at: apiKeysTable.created_at,
        is_active: apiKeysTable.is_active,
        user_id: apiKeysTable.user_id,
      })
      .from(apiKeysTable)
      .where(
        and(
          or(
            isNull(apiKeysTable.user_id), // Public API keys
            eq(apiKeysTable.user_id, userId), // User's own API keys
          ),
          isNull(apiKeysTable.session_id), // kcw session keys are machine-managed
        ),
      )
      .orderBy(desc(apiKeysTable.created_at));
  }

  async findByUuid(uuid: string, userId: string) {
    const [apiKey] = await db
      .select({
        uuid: apiKeysTable.uuid,
        name: apiKeysTable.name,
        key: displayKey,
        created_at: apiKeysTable.created_at,
        is_active: apiKeysTable.is_active,
        user_id: apiKeysTable.user_id,
      })
      .from(apiKeysTable)
      .where(
        and(eq(apiKeysTable.uuid, uuid), eq(apiKeysTable.user_id, userId)),
      );

    return apiKey;
  }

  // Find API key by UUID with access control (user can access their own keys + public keys)
  async findByUuidWithAccess(uuid: string, userId?: string) {
    const [apiKey] = await db
      .select({
        uuid: apiKeysTable.uuid,
        name: apiKeysTable.name,
        key: displayKey,
        created_at: apiKeysTable.created_at,
        is_active: apiKeysTable.is_active,
        user_id: apiKeysTable.user_id,
      })
      .from(apiKeysTable)
      .where(
        and(
          eq(apiKeysTable.uuid, uuid),
          userId
            ? or(
                isNull(apiKeysTable.user_id), // Public API keys
                eq(apiKeysTable.user_id, userId), // User's own API keys
              )
            : isNull(apiKeysTable.user_id), // Only public if no user context
        ),
      );

    return apiKey;
  }

  async validateApiKey(key: string): Promise<{
    valid: boolean;
    user_id?: string | null;
    key_uuid?: string;
    session_id?: string | null;
    endpoint_names?: string[] | null;
  }> {
    const columns = {
      uuid: apiKeysTable.uuid,
      user_id: apiKeysTable.user_id,
      is_active: apiKeysTable.is_active,
      revoked_at: apiKeysTable.revoked_at,
      session_id: apiKeysTable.session_id,
      endpoint_names: apiKeysTable.endpoint_names,
      // Evaluated by the database so every instance uses the same clock
      expired: sql<boolean>`${apiKeysTable.expires_at} IS NOT NULL AND ${apiKeysTable.expires_at} <= now()`,
    };
    let [apiKey] = await db
      .select(columns)
      .from(apiKeysTable)
      .where(eq(apiKeysTable.key, hashApiKey(key)));

    if (!apiKey) {
      // A key inserted in plaintext by an older instance that was still running
      // while this version was deployed (such rows have no prefix): accept it
      // once and convert it to the hashed form.
      [apiKey] = await db
        .select(columns)
        .from(apiKeysTable)
        .where(and(eq(apiKeysTable.key, key), eq(apiKeysTable.key_prefix, "")));
      if (apiKey) {
        await db
          .update(apiKeysTable)
          .set({ key: hashApiKey(key), key_prefix: apiKeyPrefix(key) })
          .where(eq(apiKeysTable.uuid, apiKey.uuid));
      }
    }

    if (!apiKey) {
      return { valid: false };
    }

    // Checked after both lookups, so a key can never get in through the
    // legacy plaintext path once it is inactive, revoked or expired.
    if (!apiKey.is_active || apiKey.revoked_at || apiKey.expired) {
      return { valid: false };
    }

    return {
      valid: true,
      user_id: apiKey.user_id,
      key_uuid: apiKey.uuid,
      session_id: apiKey.session_id,
      endpoint_names: apiKey.endpoint_names,
    };
  }

  /**
   * Mints the key of a kcw session. A session has at most one live key: any
   * earlier key of the same session is revoked in the same transaction.
   */
  async createSessionKey(input: {
    session_id: string;
    ttl_seconds: number;
    user_id: string | null;
    endpoint_names?: string[];
  }): Promise<{
    key: string;
    key_uuid: string;
    expires_at: Date;
  }> {
    const key = this.generateApiKey();

    return await db.transaction(async (tx) => {
      await tx
        .update(apiKeysTable)
        .set({ revoked_at: sql`now()` })
        .where(
          and(
            eq(apiKeysTable.session_id, input.session_id),
            isNull(apiKeysTable.revoked_at),
          ),
        );

      const [created] = await tx
        .insert(apiKeysTable)
        .values({
          // Unique per mint: a revoked key of the same session keeps its name
          name: kcwSessionKeyName(input.session_id, Date.now().toString(36)),
          key: hashApiKey(key),
          key_prefix: apiKeyPrefix(key),
          user_id: input.user_id,
          session_id: input.session_id,
          endpoint_names: input.endpoint_names ?? null,
          expires_at: sql`now() + make_interval(secs => ${input.ttl_seconds})`,
        })
        .returning({
          uuid: apiKeysTable.uuid,
          expires_at: apiKeysTable.expires_at,
        });

      if (!created?.expires_at) {
        throw new Error("Failed to create session API key");
      }

      return {
        key,
        key_uuid: created.uuid,
        expires_at: created.expires_at,
      };
    });
  }

  /** Revokes the live key of a session; true when there was one. */
  async revokeBySessionId(sessionId: string): Promise<boolean> {
    const revoked = await db
      .update(apiKeysTable)
      .set({ revoked_at: sql`now()` })
      .where(
        and(
          eq(apiKeysTable.session_id, sessionId),
          isNull(apiKeysTable.revoked_at),
        ),
      )
      .returning({ uuid: apiKeysTable.uuid });
    return revoked.length > 0;
  }

  /** Deletes session keys that expired or were revoked before `olderThan`. */
  async deleteExpiredSessionKeys(olderThan: Date): Promise<number> {
    const deleted = await db
      .delete(apiKeysTable)
      .where(
        and(
          sql`${apiKeysTable.session_id} IS NOT NULL`,
          or(
            lt(apiKeysTable.expires_at, olderThan),
            lt(apiKeysTable.revoked_at, olderThan),
          ),
        ),
      )
      .returning({ uuid: apiKeysTable.uuid });
    return deleted.length;
  }

  // Public keys (user_id NULL) can only be changed when `allowPublic` (admins).
  async update(
    uuid: string,
    userId: string,
    input: ApiKeyUpdateInput,
    allowPublic = false,
  ) {
    const [updatedApiKey] = await db
      .update(apiKeysTable)
      .set({
        ...(input.name && { name: input.name }),
        ...(input.is_active !== undefined && { is_active: input.is_active }),
      })
      .where(
        and(
          eq(apiKeysTable.uuid, uuid),
          or(
            eq(apiKeysTable.user_id, userId),
            allowPublic ? isNull(apiKeysTable.user_id) : undefined,
          ),
        ),
      )
      .returning({
        uuid: apiKeysTable.uuid,
        name: apiKeysTable.name,
        key: displayKey,
        created_at: apiKeysTable.created_at,
        is_active: apiKeysTable.is_active,
      });

    if (!updatedApiKey) {
      throw new Error("Failed to update API key or API key not found");
    }

    return updatedApiKey;
  }

  async delete(uuid: string, userId: string, allowPublic = false) {
    const [deletedApiKey] = await db
      .delete(apiKeysTable)
      .where(
        and(
          eq(apiKeysTable.uuid, uuid),
          or(
            eq(apiKeysTable.user_id, userId),
            allowPublic ? isNull(apiKeysTable.user_id) : undefined,
          ),
        ),
      )
      .returning({
        uuid: apiKeysTable.uuid,
        name: apiKeysTable.name,
      });

    if (!deletedApiKey) {
      throw new Error("Failed to delete API key or API key not found");
    }

    return deletedApiKey;
  }

  /**
   * Removes a key by its exact name. Only for system-generated keys: their
   * names (see lib/reserved-key-names) cannot be created or renamed to by
   * users, so no user's key can share the name.
   */
  async deleteByName(name: string): Promise<void> {
    await db.delete(apiKeysTable).where(eq(apiKeysTable.name, name));
  }
}
