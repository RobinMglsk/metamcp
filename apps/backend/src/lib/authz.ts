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
