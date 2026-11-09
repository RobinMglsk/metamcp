import express from "express";

import logger from "@/utils/logger";

import { isAdmin } from "../lib/authz";
import type { ApiKeyAuthenticatedRequest } from "./api-key-oauth.middleware";

/**
 * These routes act on server state, not just on an endpoint, so holding a key
 * for the endpoint is not enough: the caller must be an administrator. When the
 * endpoint has no authentication there is no caller at all, which is refused.
 */
export const requireAdminPrincipal = async (
  req: express.Request,
  res: express.Response,
  next: express.NextFunction,
) => {
  try {
    const authReq = req as ApiKeyAuthenticatedRequest;
    const userId = authReq.apiKeyUserId ?? authReq.oauthUserId;
    if (!(await isAdmin(userId))) {
      return res.status(403).json({
        error: "forbidden",
        message:
          "Administrator access required: authenticate with an administrator's API key or OAuth token",
      });
    }
    next();
  } catch (error) {
    logger.error("Admin API: error checking administrator access:", error);
    return res.status(500).json({ error: "Authorization check failed" });
  }
};
