import type express from "express";

import { auth } from "../auth";

/** True when the request's cookies identify a valid Better Auth session. */
export async function hasValidSession(req: express.Request): Promise<boolean> {
  if (!req.headers.cookie) return false;
  const url = new URL("/api/auth/get-session", `http://${req.headers.host}`);
  const headers = new Headers();
  headers.set("cookie", req.headers.cookie);
  const response = await auth.handler(
    new Request(url.toString(), { method: "GET", headers }),
  );
  if (!response.ok) return false;
  const data = (await response.json()) as { user?: unknown } | null;
  return !!data?.user;
}
