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
