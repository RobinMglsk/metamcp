import {
  KCW_MAX_KEY_TTL_SECONDS,
  KcwMintKeyRequestSchema,
  KcwSessionIdSchema,
} from "@repo/zod-types";
import express from "express";

import logger from "@/utils/logger";

import { ApiKeysRepository } from "../db/repositories/api-keys.repo";
import { requireKcwServiceToken } from "../middleware/kcw-service-token.middleware";

const apiKeysRepository = new ApiKeysRepository();

const kcwKeysRouter = express.Router();

kcwKeysRouter.use(requireKcwServiceToken);

// Mint the API key of a kcw session (replaces the session's earlier key)
kcwKeysRouter.post("/keys", async (req, res) => {
  const parsed = KcwMintKeyRequestSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({
      error: "invalid_request",
      details: parsed.error.issues.map((i) => ({
        path: i.path.join("."),
        message: i.message,
      })),
    });
  }

  const { session_id, ttl_seconds, endpoint_names } = parsed.data;
  try {
    const created = await apiKeysRepository.createSessionKey({
      session_id,
      ttl_seconds: Math.min(
        ttl_seconds ?? KCW_MAX_KEY_TTL_SECONDS,
        KCW_MAX_KEY_TTL_SECONDS,
      ),
      // One shared owner; unset = public key
      user_id: process.env.KCW_KEY_OWNER_USER_ID || null,
      endpoint_names,
    });

    res.setHeader("Cache-Control", "no-store");
    return res.status(201).json({
      key: created.key,
      key_uuid: created.key_uuid,
      expires_at: created.expires_at.toISOString(),
    });
  } catch (error) {
    logger.error("kcw keys: error minting session key:", error);
    return res.status(500).json({ error: "Failed to create API key" });
  }
});

// Revoke the key of a session; idempotent
kcwKeysRouter.delete("/keys/:sessionId", async (req, res) => {
  const sessionId = KcwSessionIdSchema.safeParse(req.params.sessionId);
  if (!sessionId.success) {
    return res.status(400).json({ error: "invalid_request" });
  }

  try {
    await apiKeysRepository.revokeBySessionId(sessionId.data);
    return res.status(204).end();
  } catch (error) {
    logger.error("kcw keys: error revoking session key:", error);
    return res.status(500).json({ error: "Failed to revoke API key" });
  }
});

export default kcwKeysRouter;
