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

/**
 * Outbound (SSRF) policy for URLs a user asks the server to contact.
 * Administrators may target internal/private addresses (that is how internal
 * MCP servers are reached); other users may not, unless the deployment opts in
 * with MCP_ALLOW_PRIVATE_URLS_FOR_ALL_USERS=true. Link-local / cloud metadata
 * addresses are refused for everyone.
 */
export async function outboundPolicyForUser(
  userId: string | undefined,
): Promise<{ allowPrivate: boolean }> {
  if (process.env.MCP_ALLOW_PRIVATE_URLS_FOR_ALL_USERS === "true") {
    return { allowPrivate: true };
  }
  return { allowPrivate: await isAdmin(userId) };
}

export const OWNER_ADMIN_ONLY_MESSAGE =
  "Access denied: only administrators can create shared (public) resources or resources owned by another user";

/**
 * Resolves the owner of a resource from the caller-supplied `user_id`.
 * `undefined` keeps `current` (the caller on create, the existing owner on
 * update). Anything else - null (shared) or another user - is administrator-only.
 *
 * On update paths call `canMutate` on the existing owner first and this second:
 * the former decides whether the caller may touch the row at all, this one
 * whether they may hand it to a different owner. Reversing the order would let a
 * non-owner probe ownership rules on rows they cannot modify.
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
