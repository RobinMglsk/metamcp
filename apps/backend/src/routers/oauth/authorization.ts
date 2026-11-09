import express from "express";

import logger from "@/utils/logger";

import { auth } from "../../auth";
import { oauthRepository } from "../../db/repositories";
import {
  renderConsentPage,
  signAuthorizationRequest,
  verifyAuthorizationRequest,
} from "./authorization-request";
import {
  generateSecureAuthCode,
  getBaseUrl,
  type OAuthParams,
  rateLimitAuth,
  validateRedirectUri,
} from "./utils";

const authorizationRouter = express.Router();

const AUTH_CODE_TTL_MS = 10 * 60 * 1000;

async function getSessionUser(
  req: express.Request,
): Promise<{ id: string; email?: string } | null> {
  if (!req.headers.cookie) return null;
  try {
    const sessionUrl = new URL("/api/auth/get-session", getBaseUrl(req));
    const headers = new Headers();
    headers.set("cookie", req.headers.cookie);
    const sessionResponse = await auth.handler(
      new Request(sessionUrl.toString(), { method: "GET", headers }),
    );
    if (!sessionResponse.ok) return null;
    const data = (await sessionResponse.json()) as {
      user?: { id: string; email?: string };
    } | null;
    return data?.user?.id ? data.user : null;
  } catch (error) {
    logger.info("Session verification failed:", error);
    return null;
  }
}

/**
 * Re-validates an authorization request against the registered client. Used
 * both when the request is first received and again right before a code is
 * issued, so that nothing carried through the login redirect is trusted.
 */
async function validateAuthorizationRequest(
  params: OAuthParams,
): Promise<{ clientName: string } | null> {
  if (
    !params.client_id ||
    !params.redirect_uri ||
    params.code_challenge_method !== "S256" ||
    !params.code_challenge ||
    !validateRedirectUri(params.redirect_uri)
  ) {
    return null;
  }
  const client = await oauthRepository.getClient(params.client_id);
  if (!client || !client.redirect_uris.includes(params.redirect_uri)) {
    return null;
  }
  return { clientName: client.client_name };
}

/**
 * Sends the user to log in if needed, otherwise shows the consent page.
 */
async function handleAuthorizationRequest(
  req: express.Request,
  res: express.Response,
  params: OAuthParams,
) {
  const user = await getSessionUser(req);
  if (!user) {
    const loginUrl = new URL("/login", getBaseUrl(req));
    loginUrl.searchParams.set(
      "callbackUrl",
      `/oauth/callback?params=${signAuthorizationRequest(params)}`,
    );
    return res.redirect(loginUrl.toString());
  }

  const client = await validateAuthorizationRequest(params);
  if (!client) {
    return res.status(400).json({
      error: "invalid_request",
      error_description: "Invalid authorization request",
    });
  }

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  return res.send(
    renderConsentPage({
      clientName: client.clientName,
      redirectUri: params.redirect_uri,
      scope: params.scope || "admin",
      userEmail: user.email,
      signedRequest: signAuthorizationRequest(params, user.id),
    }),
  );
}

/**
 * OAuth 2.0 Authorization Endpoint
 * Handles authorization requests from MCP clients
 */
authorizationRouter.get("/oauth/authorize", rateLimitAuth, async (req, res) => {
  try {
    const {
      response_type,
      client_id,
      redirect_uri,
      scope,
      state,
      code_challenge,
      code_challenge_method,
    } = req.query;

    logger.info("OAuth authorize request:", {
      response_type,
      client_id,
      redirect_uri,
      scope,
      state,
      code_challenge_method,
    });

    // Validate required parameters
    if (response_type !== "code") {
      return res.status(400).json({
        error: "unsupported_response_type",
        error_description: "Only 'code' response type is supported",
      });
    }

    if (!client_id || !redirect_uri) {
      return res.status(400).json({
        error: "invalid_request",
        error_description:
          "Missing required parameters: client_id or redirect_uri",
      });
    }

    // OAuth 2.1 Security: Enforce PKCE for all clients
    if (!code_challenge || !code_challenge_method) {
      return res.status(400).json({
        error: "invalid_request",
        error_description:
          "PKCE parameters (code_challenge and code_challenge_method) are required per OAuth 2.1",
      });
    }

    // Validate PKCE method (OAuth 2.1 recommends S256)
    if (code_challenge_method !== "S256") {
      return res.status(400).json({
        error: "invalid_request",
        error_description: "Unsupported code_challenge_method. Supported: S256",
      });
    }

    // OAuth 2.1 Security: Validate redirect URI format
    if (!validateRedirectUri(redirect_uri as string)) {
      return res.status(400).json({
        error: "invalid_request",
        error_description: "Invalid redirect_uri format or insecure scheme",
      });
    }

    // Validate client_id against registered clients
    const clientData = await oauthRepository.getClient(client_id as string);
    const finalClientId = client_id as string; // Track which client_id to use

    if (!clientData) {
      // Client not found - direct them to use dynamic client registration
      const baseUrl = getBaseUrl(req);
      return res.status(400).json({
        error: "invalid_client",
        error_description:
          "Client not registered. Please register your client first.",
        registration_endpoint: `${baseUrl}/oauth/register`,
        documentation:
          "Use the registration endpoint to dynamically register your OAuth client before authorization.",
      });
    } else {
      // Validate redirect_uri against registered redirect_uris for existing clients
      if (!clientData.redirect_uris.includes(redirect_uri as string)) {
        return res.status(400).json({
          error: "invalid_request",
          error_description: "redirect_uri is not registered for this client",
        });
      }
    }

    // Store OAuth parameters for later use (using the correct client_id)
    const oauthParams: OAuthParams = {
      client_id: finalClientId,
      redirect_uri: redirect_uri as string,
      scope: scope ? (scope as string) : "admin",
      state: state ? (state as string) : undefined,
      code_challenge: code_challenge ? (code_challenge as string) : undefined,
      code_challenge_method: code_challenge_method
        ? (code_challenge_method as string)
        : undefined,
    };

    logger.info(
      `Using client_id: ${finalClientId} (original: ${client_id}) for redirect_uri: ${redirect_uri}`,
    );

    // Never issue a code straight from /authorize: the (possibly logged-in)
    // user must explicitly approve the request on the consent page.
    return handleAuthorizationRequest(req, res, oauthParams);
  } catch (error) {
    logger.error("Error in OAuth authorize endpoint:", error);
    res.status(500).json({
      error: "server_error",
      error_description: "Internal server error",
    });
  }
});

/**
 * OAuth 2.0 Callback Handler
 * Entry point after the frontend login. The parameters are only accepted if
 * they carry a valid signature minted by /oauth/authorize; the user is then
 * shown the consent page.
 */
authorizationRouter.get("/oauth/callback", async (req, res) => {
  try {
    const params = verifyAuthorizationRequest(req.query.params);
    if (!params) {
      return res.status(400).json({
        error: "invalid_request",
        error_description: "Invalid or expired authorization request",
      });
    }
    return handleAuthorizationRequest(req, res, params);
  } catch (error) {
    logger.error("Error in OAuth callback:", error);
    res.status(500).send("OAuth callback error");
  }
});

/**
 * Consent submission. The signed request is bound to the user who was shown
 * the consent page, so it cannot be replayed by another account (CSRF).
 */
authorizationRouter.post("/oauth/consent", async (req, res) => {
  try {
    const user = await getSessionUser(req);
    if (!user) {
      return res.status(401).json({
        error: "login_required",
        error_description: "You must be logged in",
      });
    }

    const params = verifyAuthorizationRequest(req.body?.request, user.id);
    if (!params || !(await validateAuthorizationRequest(params))) {
      return res.status(400).json({
        error: "invalid_request",
        error_description: "Invalid or expired authorization request",
      });
    }

    const redirectUrl = new URL(params.redirect_uri);

    if (req.body?.decision !== "approve") {
      redirectUrl.searchParams.set("error", "access_denied");
      if (params.state) redirectUrl.searchParams.set("state", params.state);
      return res.redirect(redirectUrl.toString());
    }

    const code = generateSecureAuthCode();
    await oauthRepository.setAuthCode(code, {
      client_id: params.client_id,
      redirect_uri: params.redirect_uri,
      scope: params.scope || "admin",
      user_id: user.id,
      code_challenge: params.code_challenge || null,
      code_challenge_method: params.code_challenge_method || null,
      expires_at: Date.now() + AUTH_CODE_TTL_MS,
    });

    redirectUrl.searchParams.set("code", code);
    if (params.state) redirectUrl.searchParams.set("state", params.state);
    return res.redirect(redirectUrl.toString());
  } catch (error) {
    logger.error("Error in OAuth consent endpoint:", error);
    res.status(500).send("OAuth consent error");
  }
});

export default authorizationRouter;
