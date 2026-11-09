import { createHmac, timingSafeEqual } from "crypto";

import type { OAuthParams } from "./utils";

const REQUEST_TTL_MS = 10 * 60 * 1000;

interface SignedPayload {
  p: OAuthParams;
  /** Account the request is bound to ("" until the user is known). */
  u: string;
  exp: number;
}

function getSecret(): string {
  const secret = process.env.BETTER_AUTH_SECRET;
  if (!secret) throw new Error("BETTER_AUTH_SECRET is required");
  return secret;
}

function mac(data: string): string {
  return createHmac("sha256", getSecret())
    .update(`metamcp-oauth-authorization-request:${data}`)
    .digest("base64url");
}

/**
 * Serialises OAuth authorization parameters into a tamper-proof token.
 * `userId` binds the token to one account so that a token minted for the
 * attacker cannot be replayed from the victim's browser (CSRF).
 */
export function signAuthorizationRequest(
  params: OAuthParams,
  userId = "",
  now = Date.now(),
): string {
  const payload: SignedPayload = {
    p: params,
    u: userId,
    exp: now + REQUEST_TTL_MS,
  };
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `${body}.${mac(body)}`;
}

/**
 * Returns the parameters if the token is authentic, unexpired and bound to
 * `expectedUserId` (use "" for tokens that are not yet bound to a user).
 */
export function verifyAuthorizationRequest(
  token: unknown,
  expectedUserId = "",
  now = Date.now(),
): OAuthParams | null {
  if (typeof token !== "string") return null;
  const dot = token.indexOf(".");
  if (dot < 1) return null;
  const body = token.slice(0, dot);
  const given = Buffer.from(token.slice(dot + 1));
  const expected = Buffer.from(mac(body));
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) {
    return null;
  }
  try {
    const payload = JSON.parse(
      Buffer.from(body, "base64url").toString(),
    ) as SignedPayload;
    if (typeof payload.exp !== "number" || now > payload.exp) return null;
    if (payload.u !== expectedUserId) return null;
    return payload.p;
  } catch {
    return null;
  }
}

export function escapeHtml(value: string): string {
  return value.replace(
    /[&<>"']/g,
    (c) =>
      ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      })[c] as string,
  );
}

export function renderConsentPage(opts: {
  clientName: string;
  redirectUri: string;
  scope: string;
  userEmail?: string;
  signedRequest: string;
}): string {
  let redirectHost = opts.redirectUri;
  try {
    redirectHost = new URL(opts.redirectUri).host;
  } catch {
    // keep the raw value
  }
  const e = escapeHtml;
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Authorize application</title>
<style>body{font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem}
button{padding:.6rem 1.2rem;margin-right:.5rem;font-size:1rem}code{word-break:break-all}</style></head>
<body>
<h1>Authorize application</h1>
<p><strong>${e(opts.clientName)}</strong> wants to access your MetaMCP account${
    opts.userEmail ? ` (<code>${e(opts.userEmail)}</code>)` : ""
  } with scope <code>${e(opts.scope)}</code>.</p>
<p>If you approve, you will be sent to <code>${e(redirectHost)}</code>. Only approve if you recognise this application.</p>
<form method="post" action="/oauth/consent">
<input type="hidden" name="request" value="${e(opts.signedRequest)}">
<button type="submit" name="decision" value="approve">Approve</button>
<button type="submit" name="decision" value="deny">Deny</button>
</form></body></html>`;
}
