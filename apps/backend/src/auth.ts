import { betterAuth } from "better-auth";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { genericOAuth, GenericOAuthConfig } from "better-auth/plugins";

import { db } from "./db/index";
import * as schema from "./db/schema";
import { configService } from "./lib/config.service";
import { enforceStartupConfig } from "./lib/config-guard";
import logger from "./utils/logger";

// Provide default values for development
if (!process.env.BETTER_AUTH_SECRET) {
  throw new Error("BETTER_AUTH_SECRET environment variable is required");
}
if (!process.env.APP_URL) {
  throw new Error("APP_URL environment variable is required");
}

const LOG_LEVELS = ["debug", "info", "warn", "error"] as const;
function resolveLogLevel(raw: string | undefined) {
  return LOG_LEVELS.find((l) => l === raw) ?? "warn";
}

// Refuse to run (in production) with placeholder secrets/passwords
enforceStartupConfig();

const BETTER_AUTH_SECRET = process.env.BETTER_AUTH_SECRET;
const BETTER_AUTH_URL = process.env.APP_URL;

// Helper function to create basic auth middleware
const createBasicAuthCheckMiddleware = () => {
  return async (request: unknown) => {
    const isBasicAuthDisabled = await configService.isBasicAuthDisabled();
    if (isBasicAuthDisabled) {
      throw new Error(
        "Basic email/password authentication is currently disabled. Please use SSO/OIDC authentication instead.",
      );
    }
    return { request };
  };
};

// OIDC Provider configuration - optional, only if environment variables are provided
const oidcProviders: GenericOAuthConfig[] = [];

// Add OIDC provider if configured
if (process.env.OIDC_CLIENT_ID && process.env.OIDC_CLIENT_SECRET) {
  const providerId = process.env.OIDC_PROVIDER_ID || "oidc";
  const oidcConfig: GenericOAuthConfig = {
    providerId,
    // better-auth >=1.7 serves generic OAuth callbacks at /api/auth/callback/:id.
    // Keep advertising the pre-1.7 URI so redirect URIs already registered at
    // identity providers keep working; src/index.ts maps it to the new route.
    redirectURI: `${BETTER_AUTH_URL}/api/auth/oauth2/callback/${providerId}`,
    clientId: process.env.OIDC_CLIENT_ID,
    clientSecret: process.env.OIDC_CLIENT_SECRET,
    scopes: (process.env.OIDC_SCOPES || "openid email profile").split(" "),
    pkce: process.env.OIDC_PKCE !== "false", // Enable PKCE by default for security
    discoveryUrl: process.env.OIDC_DISCOVERY_URL,
    authorizationUrl: process.env.OIDC_AUTHORIZATION_URL, //this is required due to a bug in better-auth: https://github.com/better-auth/better-auth/issues/3278
  };

  oidcProviders.push(oidcConfig);
  logger.info(`✓ OIDC Provider configured: ${oidcConfig.providerId}`);
}

// Default trusted origins for development
const DEFAULT_TRUSTED_ORIGINS = [
  "http://localhost",
  "http://localhost:3000",
  "http://localhost:12008",
  "http://127.0.0.1",
  "http://127.0.0.1:12008",
  "http://127.0.0.1:3000",
  "http://0.0.0.0",
  "http://0.0.0.0:3000",
  "http://0.0.0.0:12008",
];

// Parse extra trusted origins from environment variable (comma-separated)
const extraTrustedOrigins = process.env.EXTRA_TRUSTED_ORIGINS
  ? process.env.EXTRA_TRUSTED_ORIGINS.split(",")
      .map((origin: string) => origin.trim())
      .filter(Boolean)
  : [];

const trustedOrigins = [...DEFAULT_TRUSTED_ORIGINS, ...extraTrustedOrigins];

export const auth = betterAuth({
  secret: BETTER_AUTH_SECRET,
  baseURL: BETTER_AUTH_URL,
  database: drizzleAdapter(db, {
    provider: "pg",
    schema: {
      user: schema.usersTable,
      session: schema.sessionsTable,
      account: schema.accountsTable,
      verification: schema.verificationsTable,
    },
  }),
  trustedOrigins,
  plugins: [
    // Add generic OAuth plugin for OIDC support
    ...(oidcProviders.length > 0
      ? [genericOAuth({ config: oidcProviders })]
      : []),
  ],
  emailAndPassword: {
    enabled: true, // This will be dynamically controlled by middleware
    requireEmailVerification: false, // Set to true if you want email verification
  },
  account: {
    accountLinking: {
      enabled: true,
      // Never link a provider account that has a different email address
      allowDifferentEmails: false,
      // A "trusted" provider may link into an existing account even when it
      // does not assert email_verified, i.e. anyone who can register the
      // victim's address at the identity provider could take over a local
      // account with that email (including a bootstrapped admin). Providers are
      // therefore only trusted when the operator opts in; otherwise the
      // provider must report the email as verified for an account to be linked.
      trustedProviders:
        process.env.OIDC_TRUST_UNVERIFIED_EMAILS === "true"
          ? oidcProviders.map((p) => p.providerId)
          : [],
      // Only link into a local account whose email has been verified, so that
      // someone who pre-registers a victim's email with a password cannot take
      // over the account when the victim later signs in through SSO. (This is
      // Better Auth's default; it is stated explicitly so it cannot silently
      // regress. The old allowSameEmail / requireEmailVerification options
      // are not part of Better Auth 1.7 and did nothing.)
      requireLocalEmailVerified: true,
    },
  },
  session: {
    // Session lifetimes are env-var configurable so deployers can tune
    // how often users re-touch the gateway via SSO without rebuilding
    // the image. Defaults match the previous hardcoded values exactly,
    // so this is a strict superset — no behavior change for existing
    // installs that don't set the env vars.
    expiresIn: (() => {
      const raw = process.env.BETTER_AUTH_SESSION_EXPIRES_IN_SECONDS;
      const parsed = raw ? Number.parseInt(raw, 10) : NaN;
      return Number.isFinite(parsed) && parsed > 0 ? parsed : 60 * 60 * 24 * 7; // 7 days (default)
    })(),
    updateAge: (() => {
      const raw = process.env.BETTER_AUTH_SESSION_UPDATE_AGE_SECONDS;
      const parsed = raw ? Number.parseInt(raw, 10) : NaN;
      return Number.isFinite(parsed) && parsed > 0 ? parsed : 60 * 60 * 24; // 1 day (default — how often the session expiry is bumped on access)
    })(),
  },
  user: {
    additionalFields: {
      // Never settable from client input (e.g. the sign-up body)
      role: {
        type: "string",
        defaultValue: "user",
        input: false,
      },
      emailVerified: {
        type: "boolean",
        defaultValue: false,
        input: false, // never settable by the client
      },
    },
  },
  advanced: {
    // Only the Better Auth client IP is taken from X-Forwarded-For, and the
    // backend overwrites that header with the IP Express resolved from its
    // trusted proxies (see index.ts), so it cannot be spoofed by clients.
    ipAddress: { ipAddressHeaders: ["x-forwarded-for"] },
    // Sharing the session cookie with sibling subdomains is opt-in
    ...(process.env.BETTER_AUTH_CROSS_SUBDOMAIN_COOKIES === "true"
      ? { crossSubDomainCookies: { enabled: true } }
      : {}),
  },
  logger: {
    level: resolveLogLevel(process.env.BETTER_AUTH_LOG_LEVEL),
  },
  databaseHooks: {
    user: {
      create: {
        before: async (user, context) => {
          // Check if signup is disabled based on the registration method
          const isSignupDisabled = await configService.isSignupDisabled();
          const isSsoSignupDisabled = await configService.isSsoSignupDisabled();

          // Determine if this is an SSO/OAuth registration by checking the request path
          // OAuth/SSO registrations typically come through callback endpoints
          const isSsoRegistration =
            context?.path?.includes("/callback/") ||
            context?.path?.includes("/oauth/") ||
            context?.path?.includes("/oidc/");

          if (isSsoRegistration) {
            if (isSsoSignupDisabled) {
              throw new Error(
                "New user registration via SSO/OAuth is currently disabled.",
              );
            }
          } else {
            if (isSignupDisabled) {
              throw new Error("New user registration is currently disabled.");
            }
          }

          // The first account on a fresh install becomes the administrator
          const [existing] = await db
            .select({ id: schema.usersTable.id })
            .from(schema.usersTable)
            .limit(1);

          return { data: existing ? user : { ...user, role: "admin" } };
        },
      },
    },
  },
  // Add middleware to check basic auth setting
  middleware: [
    {
      path: "/sign-in/email",
      middleware: createBasicAuthCheckMiddleware(),
    },
    {
      path: "/sign-up/email",
      middleware: createBasicAuthCheckMiddleware(),
    },
    {
      path: "/forgot-password",
      middleware: createBasicAuthCheckMiddleware(),
    },
    {
      path: "/reset-password",
      middleware: createBasicAuthCheckMiddleware(),
    },
  ],
});

console.log("✓ Better Auth instance created successfully");
console.log(`✓ OIDC Providers configured: ${oidcProviders.length}`);

export type Session = typeof auth.$Infer.Session;
// Note: User type needs to be inferred from Session.user
export type User = typeof auth.$Infer.Session.user;
