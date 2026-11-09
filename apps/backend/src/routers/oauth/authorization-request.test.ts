import { beforeEach, describe, expect, it } from "vitest";

import {
  escapeHtml,
  renderConsentPage,
  signAuthorizationRequest,
  verifyAuthorizationRequest,
} from "./authorization-request";

const params = {
  client_id: "mcp_client_x",
  redirect_uri: "https://client.example/cb",
  scope: "admin",
  state: "s",
  code_challenge: "abc",
  code_challenge_method: "S256",
};

beforeEach(() => {
  process.env.BETTER_AUTH_SECRET = "test-secret";
});

describe("signed authorization requests", () => {
  it("round-trips unbound parameters", () => {
    expect(
      verifyAuthorizationRequest(signAuthorizationRequest(params)),
    ).toEqual(params);
  });

  it("rejects unsigned, forged and tampered tokens", () => {
    const forged = Buffer.from(
      JSON.stringify({ p: params, u: "", exp: Date.now() + 1e6 }),
    ).toString("base64url");
    expect(verifyAuthorizationRequest(forged)).toBeNull();
    expect(verifyAuthorizationRequest(`${forged}.AAAA`)).toBeNull();
    expect(verifyAuthorizationRequest(undefined)).toBeNull();

    const token = signAuthorizationRequest(params);
    const [body, sig] = token.split(".");
    const evil = Buffer.from(
      JSON.stringify({
        p: { ...params, redirect_uri: "https://evil.example" },
        u: "",
        exp: Date.now() + 1e6,
      }),
    ).toString("base64url");
    expect(verifyAuthorizationRequest(`${evil}.${sig}`)).toBeNull();
    expect(verifyAuthorizationRequest(`${body}.${sig}`)).not.toBeNull();
  });

  it("rejects tokens signed with another secret", () => {
    const token = signAuthorizationRequest(params);
    process.env.BETTER_AUTH_SECRET = "other";
    expect(verifyAuthorizationRequest(token)).toBeNull();
  });

  it("expires after 10 minutes", () => {
    const token = signAuthorizationRequest(params, "", 0);
    expect(verifyAuthorizationRequest(token, "", 9 * 60 * 1000)).not.toBeNull();
    expect(verifyAuthorizationRequest(token, "", 11 * 60 * 1000)).toBeNull();
  });

  it("is bound to the user it was minted for", () => {
    const token = signAuthorizationRequest(params, "attacker");
    expect(verifyAuthorizationRequest(token, "attacker")).toEqual(params);
    expect(verifyAuthorizationRequest(token, "victim")).toBeNull();
    expect(verifyAuthorizationRequest(token)).toBeNull();
  });
});

describe("consent page", () => {
  it("escapes attacker-controlled client names", () => {
    const html = renderConsentPage({
      clientName: '<script>alert(1)</script>"',
      redirectUri: "https://client.example/cb",
      scope: "admin",
      signedRequest: "x.y",
    });
    expect(html).not.toContain("<script>");
    expect(html).toContain("&lt;script&gt;");
    expect(html).toContain("client.example");
  });

  it("escapes html", () => {
    expect(escapeHtml(`<a href="x">&'`)).toBe(
      "&lt;a href=&quot;x&quot;&gt;&amp;&#39;",
    );
  });
});
