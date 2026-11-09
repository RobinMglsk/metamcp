import { eq } from "drizzle-orm";

import { db } from "../db";
import { usersTable } from "../db/schema";

export const ADMIN_ROLE = "admin";

/**
 * Looks the role up in the database (never from the request) so that a stale
 * or forged session payload cannot grant privileges.
 */
export async function isAdmin(userId: string | undefined): Promise<boolean> {
  if (!userId) return false;
  const [row] = await db
    .select({ role: usersTable.role })
    .from(usersTable)
    .where(eq(usersTable.id, userId))
    .limit(1);
  return row?.role === ADMIN_ROLE;
}

export const STDIO_ADMIN_ONLY_MESSAGE =
  "Access denied: only administrators can create or modify STDIO (command-based) MCP servers";

/**
 * Shared (user_id = null) resources may only be modified by administrators;
 * private resources only by their owner.
 */
export async function canMutate(
  ownerId: string | null | undefined,
  userId: string,
): Promise<boolean> {
  if (ownerId === null || ownerId === undefined) return isAdmin(userId);
  return ownerId === userId;
}

/** Message for a denied mutation: explains the admin-only rule for shared resources. */
export function denyMessage(
  ownerId: string | null | undefined,
  fallback: string,
): string {
  return ownerId === null || ownerId === undefined
    ? SHARED_ADMIN_ONLY_MESSAGE
    : fallback;
}

export const SHARED_ADMIN_ONLY_MESSAGE =
  "Access denied: only administrators can modify shared (public) resources";

export const OWNER_ADMIN_ONLY_MESSAGE =
  "Access denied: only administrators can create shared (public) resources or resources owned by another user";

/**
 * Resolves the owner of a resource from the caller-supplied `user_id`.
 * `undefined` keeps `current` (the caller on create, the existing owner on
 * update). Anything else - null (shared) or another user - is administrator-only.
 */
export async function resolveOwner(
  requested: string | null | undefined,
  current: string | null,
  userId: string,
): Promise<{ ok: true; ownerId: string | null } | { ok: false }> {
  if (requested === undefined) return { ok: true, ownerId: current };
  if (requested === current || requested === userId) {
    return { ok: true, ownerId: requested };
  }
  return (await isAdmin(userId))
    ? { ok: true, ownerId: requested }
    : { ok: false };
}
