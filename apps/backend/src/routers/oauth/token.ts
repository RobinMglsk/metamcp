import express from "express";

import logger from "@/utils/logger";

import { oauthRepository } from "../../db/repositories";
import { authenticateClient, upgradeLegacySecret } from "./client-auth";
import {
  generateSecureAccessToken,
  generateSecureRefreshToken,
  rateLimitToken,
} from "./utils";

const tokenRouter = express.Router();

const ACCESS_TOKEN_EXPIRY = 3600; // 1 hour
const REFRESH_TOKEN_EXPIRY = 7 * 24 * 3600; // 7 days

/**
 * Issue a new access token + refresh token pair and store them.
 */
async function issueTokenPair(clientId: string, userId: string, scope: string) {
  const accessToken = generateSecureAccessToken();
  const refreshToken = generateSecureRefreshToken();

  await oauthRepository.setAccessToken(accessToken, {
    client_id: clientId,
    user_id: userId,
    scope,
    expires_at: Date.now() + ACCESS_TOKEN_EXPIRY * 1000,
    refresh_token: refreshToken,
    refresh_token_expires_at: Date.now() + REFRESH_TOKEN_EXPIRY * 1000,
  });

  return { accessToken, refreshToken };
}

/**
 * OAuth 2.0 Token Endpoint
 * Handles token exchange requests from MCP clients
 * Supports authorization_code and refresh_token grant types
 */
tokenRouter.post("/oauth/token", rateLimitToken, async (req, res) => {
  try {
    // Check if body was parsed correctly
    if (!req.body || typeof req.body !== "object") {
      logger.error("Token endpoint: req.body is undefined or invalid", {
        body: req.body,
        bodyType: typeof req.body,
        contentType: req.headers["content-type"],
        method: req.method,
      });
      return res.status(400).json({
        error: "invalid_request",
        error_description:
          "Request body is missing or malformed. Ensure Content-Type is application/json or application/x-www-form-urlencoded",
      });
    }

    const { grant_type } = req.body;

    if (grant_type === "refresh_token") {
      return handleRefreshTokenGrant(req, res);
    }

    if (grant_type === "authorization_code") {
      return handleAuthorizationCodeGrant(req, res);
    }

    return res.status(400).json({
      error: "unsupported_grant_type",
      error_description:
        "Supported grant types: authorization_code, refresh_token",
    });
  } catch (error) {
    logger.error("Error in OAuth token endpoint:", error);
    res.status(500).json({
      error: "server_error",
      error_description: "Internal server error",
    });
  }
});

/**
 * Handle grant_type=authorization_code
 */
async function handleAuthorizationCodeGrant(
  req: express.Request,
  res: express.Response,
) {
  const { code, redirect_uri, client_id, code_verifier } = req.body;

  // Validate authorization code
  if (!code) {
    return res.status(400).json({
      error: "invalid_request",
      error_description: "Missing authorization code",
    });
  }

  // Look up and consume the authorization code in one step: it is single use,
  // so of two concurrent redemptions only one succeeds. A failed attempt (wrong
  // client secret, redirect_uri or PKCE verifier) burns the code as well, as
  // RFC 6749 4.1.2 recommends: a client with a transient problem must restart
  // the authorization flow.
  const codeData = await oauthRepository.consumeAuthCode(code);
  if (!codeData) {
    return res.status(400).json({
      error: "invalid_grant",
      error_description: "Invalid or expired authorization code",
    });
  }

  // Check if code has expired (10 minutes)
  if (Date.now() > codeData.expires_at.getTime()) {
    return res.status(400).json({
      error: "invalid_grant",
      error_description: "Authorization code has expired",
    });
  }

  // Validate client_id and redirect_uri match the original request
  if (codeData.client_id !== client_id) {
    return res.status(400).json({
      error: "invalid_client",
      error_description: "Client ID does not match",
    });
  }

  if (codeData.redirect_uri !== redirect_uri) {
    return res.status(400).json({
      error: "invalid_grant",
      error_description: "Redirect URI does not match",
    });
  }

  // Validate client_id against registered clients
  const clientData = await oauthRepository.getClient(client_id);
  if (!clientData) {
    return res.status(400).json({
      error: "invalid_client",
      error_description: "Client not found or not registered",
    });
  }

  // Validate client authentication based on registered auth method
  const clientAuthError = authenticateClient(req, clientData);
  if (clientAuthError) {
    return res.status(clientAuthError.status).json(clientAuthError.body);
  }
  await upgradeLegacySecret(req, clientData, (id, hashed) =>
    oauthRepository.upgradeClientSecret(id, hashed),
  );

  // OAuth 2.1 Security: PKCE is mandatory for all clients
  if (!codeData.code_challenge) {
    return res.status(400).json({
      error: "invalid_grant",
      error_description:
        "Authorization code was not issued with PKCE challenge",
    });
  }

  if (!code_verifier) {
    return res.status(400).json({
      error: "invalid_request",
      error_description: "PKCE code verifier is required",
    });
  }

  // Verify code challenge
  const crypto = await import("crypto");
  let challengeFromVerifier: string;

  if (codeData.code_challenge_method === "S256") {
    const hash = crypto.createHash("sha256").update(code_verifier).digest();
    challengeFromVerifier = hash.toString("base64url");
  } else if (codeData.code_challenge_method === "plain") {
    challengeFromVerifier = code_verifier;
  } else {
    return res.status(400).json({
      error: "invalid_grant",
      error_description: "Unsupported code challenge method",
    });
  }

  if (challengeFromVerifier !== codeData.code_challenge) {
    return res.status(400).json({
      error: "invalid_grant",
      error_description: "PKCE verification failed",
    });
  }

  // Issue access token + refresh token
  const { accessToken, refreshToken } = await issueTokenPair(
    codeData.client_id,
    codeData.user_id,
    codeData.scope,
  );

  res.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: ACCESS_TOKEN_EXPIRY,
    refresh_token: refreshToken,
    scope: codeData.scope,
  });
}

/**
 * Handle grant_type=refresh_token
 * Issues a new access token + refresh token pair (token rotation).
 */
async function handleRefreshTokenGrant(
  req: express.Request,
  res: express.Response,
) {
  const { refresh_token, client_id } = req.body;

  if (!refresh_token) {
    return res.status(400).json({
      error: "invalid_request",
      error_description: "Missing refresh_token parameter",
    });
  }

  // Look up the token row by refresh_token
  const tokenData = await oauthRepository.getByRefreshToken(refresh_token);
  if (!tokenData) {
    return res.status(400).json({
      error: "invalid_grant",
      error_description: "Invalid refresh token",
    });
  }

  // Check refresh token expiry
  if (
    tokenData.refresh_token_expires_at &&
    Date.now() > tokenData.refresh_token_expires_at.getTime()
  ) {
    await oauthRepository.deleteAccessTokenByHash(tokenData.access_token);
    return res.status(400).json({
      error: "invalid_grant",
      error_description: "Refresh token has expired",
    });
  }

  // Validate client_id matches (if provided)
  if (client_id && tokenData.client_id !== client_id) {
    return res.status(400).json({
      error: "invalid_client",
      error_description: "Client ID does not match",
    });
  }

  // Confidential clients must authenticate on refresh as well
  const refreshClient = await oauthRepository.getClient(tokenData.client_id);
  if (!refreshClient) {
    return res.status(400).json({
      error: "invalid_client",
      error_description: "Client not found or not registered",
    });
  }
  const refreshAuthError = authenticateClient(req, refreshClient);
  if (refreshAuthError) {
    return res.status(refreshAuthError.status).json(refreshAuthError.body);
  }
  await upgradeLegacySecret(req, refreshClient, (id, hashed) =>
    oauthRepository.upgradeClientSecret(id, hashed),
  );

  // Delete old token row (rotation: old refresh token is single-use)
  await oauthRepository.deleteAccessTokenByHash(tokenData.access_token);

  // Issue new access token + refresh token
  const { accessToken, refreshToken } = await issueTokenPair(
    tokenData.client_id,
    tokenData.user_id,
    tokenData.scope,
  );

  res.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: ACCESS_TOKEN_EXPIRY,
    refresh_token: refreshToken,
    scope: tokenData.scope,
  });
}

/**
 * OAuth 2.0 Token Introspection Endpoint
 * Allows clients to introspect access tokens
 */
tokenRouter.post("/oauth/introspect", async (req, res) => {
  try {
    // Check if body was parsed correctly
    if (!req.body || typeof req.body !== "object") {
      return res.status(400).json({
        error: "invalid_request",
        error_description: "Request body is missing or malformed",
      });
    }

    const { token } = req.body;

    if (!token) {
      return res.status(400).json({
        error: "invalid_request",
        error_description: "Missing token parameter",
      });
    }

    // Check if token exists and is valid
    const tokenData = await oauthRepository.getAccessToken(token);

    if (!tokenData || !token.startsWith("mcp_token_")) {
      return res.json({
        active: false,
      });
    }

    // Check if token has expired
    if (Date.now() > tokenData.expires_at.getTime()) {
      await oauthRepository.deleteAccessToken(token);
      return res.json({
        active: false,
      });
    }

    // Token is active, return introspection details
    res.json({
      active: true,
      scope: tokenData.scope,
      client_id: tokenData.client_id,
      token_type: "Bearer",
      exp: Math.floor(tokenData.expires_at.getTime() / 1000),
      iat: Math.floor(tokenData.created_at.getTime() / 1000),
      sub: tokenData.user_id,
    });
  } catch (error) {
    logger.error("Error in OAuth introspect endpoint:", error);
    res.status(500).json({
      error: "server_error",
      error_description: "Internal server error",
    });
  }
});

/**
 * OAuth 2.0 Token Revocation Endpoint
 * Allows clients to revoke access tokens or refresh tokens
 */
tokenRouter.post("/oauth/revoke", async (req, res) => {
  try {
    // Check if body was parsed correctly
    if (!req.body || typeof req.body !== "object") {
      return res.status(400).json({
        error: "invalid_request",
        error_description: "Request body is missing or malformed",
      });
    }

    const { token } = req.body;

    if (!token) {
      return res.status(400).json({
        error: "invalid_request",
        error_description: "Missing token parameter",
      });
    }

    // Try revoking as access token
    if (await oauthRepository.getAccessToken(token)) {
      await oauthRepository.deleteAccessToken(token);
    } else {
      // Try revoking as refresh token
      const tokenData = await oauthRepository.getByRefreshToken(token);
      if (tokenData) {
        await oauthRepository.deleteAccessTokenByHash(tokenData.access_token);
      }
      // RFC 7009: return success even if token doesn't exist
    }

    // RFC 7009 specifies that revocation endpoint should return 200 OK
    res.status(200).send();
  } catch (error) {
    logger.error("Error in OAuth revoke endpoint:", error);
    res.status(500).json({
      error: "server_error",
      error_description: "Internal server error",
    });
  }
});

export default tokenRouter;
