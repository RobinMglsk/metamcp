import { createHash, timingSafeEqual } from "crypto";
import express from "express";

import { AuthRateLimiter } from "../lib/auth-rate-limiter";

// Separate from the endpoint limiter, so failed attempts against the kcw
// routes cannot lock out real endpoint users (and the other way round).
export const kcwAuthRateLimiter = new AuthRateLimiter(10, 60 * 1000);

const digest = (value: string) => createHash("sha256").update(value).digest();

/**
 * The kcw routes mint API keys, so they are only reachable with the shared
 * service token. Without KCW_SERVICE_TOKEN the feature is off and the routes
 * do not exist (404).
 */
export const requireKcwServiceToken = (
  req: express.Request,
  res: express.Response,
  next: express.NextFunction,
) => {
  const expected = process.env.KCW_SERVICE_TOKEN;
  if (!expected) {
    return res.status(404).json({ error: "Not found" });
  }

  const header = req.headers.authorization;
  const presented = header?.startsWith("Bearer ") ? header.substring(7) : "";
  // Hashing first gives equal lengths, which timingSafeEqual requires
  if (presented && timingSafeEqual(digest(presented), digest(expected))) {
    return next();
  }

  // isRateLimited counts this failed attempt itself
  if (kcwAuthRateLimiter.isRateLimited(`kcw:${req.ip ?? "unknown"}`)) {
    return res.status(429).json({ error: "too_many_requests" });
  }
  return res.status(401).json({ error: "invalid_service_token" });
};
