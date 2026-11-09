import type express from "express";

import { auth, type Session, type User } from "../auth";

export interface RequestSession {
  user?: User;
  session?: Session;
}

/**
 * Resolves the Better Auth session from the request's cookies. The single
 * definition of "signed in" shared by the tRPC context and the body-limit
 * middleware: both a user and a session must be present. Throws if the lookup
 * itself fails (callers decide how to degrade).
 */
export async function getSessionFromRequest(
  req: express.Request,
): Promise<RequestSession> {
  if (!req.headers.cookie) return {};

  const url = new URL("/api/auth/get-session", `http://${req.headers.host}`);
  const headers = new Headers();
  headers.set("cookie", req.headers.cookie);
  const response = await auth.handler(
    new Request(url.toString(), { method: "GET", headers }),
  );
  if (!response.ok) return {};

  const data = (await response.json()) as RequestSession | null;
  return data?.user && data?.session
    ? { user: data.user, session: data.session }
    : {};
}

/** True when the request's cookies identify a valid session. */
export async function hasValidSession(req: express.Request): Promise<boolean> {
  const { user, session } = await getSessionFromRequest(req);
  return !!(user && session);
}
