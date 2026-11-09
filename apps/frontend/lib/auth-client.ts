import { createAuthClient } from "better-auth/react";

import { getAppUrl } from "./env";

// Generic OAuth (OIDC) providers are exposed as social providers since
// better-auth 1.7, so sign in with `authClient.signIn.social({ provider })`.
export const authClient = createAuthClient({
  baseURL: getAppUrl(),
}) as ReturnType<typeof createAuthClient>;
