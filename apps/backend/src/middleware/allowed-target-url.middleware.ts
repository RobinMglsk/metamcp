import { McpServerTypeEnum } from "@repo/zod-types";
import express from "express";

import logger from "@/utils/logger";

import { outboundPolicyForUser } from "../lib/authz";
import { assertOutboundUrlAllowed, OutboundUrlError } from "../lib/ssrf-guard";

/**
 * The inspector proxy fetches whatever URL the caller supplies: refuse targets
 * the caller's outbound policy does not allow (metadata/link-local for
 * everyone, private networks for non-admins). Needs the authenticated user on
 * `req.user` (set by betterAuthMcpMiddleware).
 */
export const createAllowedTargetUrlMiddleware =
  (
    transformUrl: (url: string) => string = (url) => url,
  ): express.RequestHandler =>
  async (req, res, next) => {
    const type = req.query.transportType;
    if (
      (type !== McpServerTypeEnum.enum.SSE &&
        type !== McpServerTypeEnum.enum.STREAMABLE_HTTP) ||
      typeof req.query.url !== "string"
    ) {
      return next();
    }
    try {
      const policy = await outboundPolicyForUser(
        (req as express.Request & { user?: { id?: string } }).user?.id,
      );
      await assertOutboundUrlAllowed(transformUrl(req.query.url), policy);
      next();
    } catch (error) {
      if (error instanceof OutboundUrlError) {
        return res
          .status(403)
          .json({ error: "Forbidden", message: error.message });
      }
      logger.error("Error validating proxy target URL:", error);
      return res.status(500).json({ error: "Authorization check failed" });
    }
  };
