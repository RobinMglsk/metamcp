// Startup checks for configuration that makes an installation trivially
// compromisable: well-known placeholder secrets and passwords copied from the
// example files. In production they stop the process; elsewhere they warn.
// ALLOW_INSECURE_DEFAULTS=true downgrades the errors to warnings (local
// evaluation only).

export interface ConfigFindings {
  errors: string[];
  warnings: string[];
}

const PLACEHOLDER_SECRET_FRAGMENTS = [
  "your-super-secret",
  "your_auth_secret",
  "your-secret",
  "change-this",
  "change-me",
  "changeme",
  "replace-me",
  "example",
];
const MIN_SECRET_LENGTH = 32;

const WEAK_PASSWORDS = new Set([
  "changeme",
  "change-me",
  "password",
  "admin",
  "admin123",
  "admin-password",
  "dev-password",
  "pass1",
  "12345678",
  "m3t4mcp",
]);

export function isPlaceholderSecret(secret: string): boolean {
  const lower = secret.toLowerCase();
  return (
    secret.length < MIN_SECRET_LENGTH ||
    PLACEHOLDER_SECRET_FRAGMENTS.some((f) => lower.includes(f))
  );
}

export function isWeakPassword(password: string): boolean {
  return password.length < 8 || WEAK_PASSWORDS.has(password.toLowerCase());
}

function databasePassword(url: string | undefined): string | undefined {
  if (!url) return undefined;
  try {
    return decodeURIComponent(new URL(url).password);
  } catch {
    return undefined;
  }
}

function bootstrapPasswords(env: Record<string, string | undefined>) {
  const passwords: string[] = [];
  if (env.BOOTSTRAP_USER_PASSWORD) passwords.push(env.BOOTSTRAP_USER_PASSWORD);
  if (env.BOOTSTRAP_USERS) {
    try {
      const users = JSON.parse(env.BOOTSTRAP_USERS);
      if (Array.isArray(users)) {
        for (const u of users) {
          if (u && typeof u.password === "string") passwords.push(u.password);
        }
      }
    } catch {
      // malformed JSON is reported by the bootstrap service itself
    }
  }
  return passwords;
}

function bootstrapEndpointsWithoutAuth(
  env: Record<string, string | undefined>,
): string[] {
  if (!env.BOOTSTRAP_ENDPOINTS) return [];
  try {
    const endpoints = JSON.parse(env.BOOTSTRAP_ENDPOINTS);
    if (!Array.isArray(endpoints)) return [];
    return endpoints
      .filter(
        (e) =>
          e &&
          e.enable_auth === false &&
          e.enable_auth_oauth !== true &&
          typeof e.name === "string",
      )
      .map((e) => e.name as string);
  } catch {
    return [];
  }
}

export function checkStartupConfig(
  env: Record<string, string | undefined>,
): ConfigFindings {
  const production = env.NODE_ENV === "production";
  const errors: string[] = [];
  const warnings: string[] = [];
  const problem = (message: string) =>
    (production ? errors : warnings).push(message);

  const secret = env.BETTER_AUTH_SECRET;
  if (secret && isPlaceholderSecret(secret)) {
    problem(
      "BETTER_AUTH_SECRET is a placeholder or shorter than 32 characters; anyone who knows it can forge sessions. Generate one with: openssl rand -base64 32",
    );
  }

  if (bootstrapPasswords(env).some(isWeakPassword)) {
    problem(
      "A BOOTSTRAP_USER_PASSWORD / BOOTSTRAP_USERS password is a well-known default or too short (the account would be created with it). Set a strong password.",
    );
  }

  const dbPassword = databasePassword(env.DATABASE_URL);
  if (dbPassword !== undefined && isWeakPassword(dbPassword)) {
    warnings.push(
      "The database password is a well-known default (such as m3t4mcp) or too short. Set a strong POSTGRES_PASSWORD.",
    );
  }

  const open = bootstrapEndpointsWithoutAuth(env);
  if (open.length > 0) {
    warnings.push(
      `BOOTSTRAP_ENDPOINTS creates endpoint(s) without authentication (${open.join(", ")}): anyone who can reach them can call every tool of their namespace.`,
    );
  }

  return { errors, warnings };
}

/** Logs the findings and exits when a production install is insecure. */
export function enforceStartupConfig(
  env: Record<string, string | undefined> = process.env,
): void {
  const { errors, warnings } = checkStartupConfig(env);
  const allowInsecure = env.ALLOW_INSECURE_DEFAULTS === "true";

  for (const w of warnings) console.warn(`⚠️  Insecure configuration: ${w}`);
  if (errors.length === 0) return;

  if (allowInsecure) {
    for (const e of errors) {
      console.warn(
        `⚠️  Insecure configuration (ALLOW_INSECURE_DEFAULTS=true): ${e}`,
      );
    }
    return;
  }

  for (const e of errors) console.error(`❌ Insecure configuration: ${e}`);
  console.error(
    "Refusing to start. Fix the values above (set ALLOW_INSECURE_DEFAULTS=true only for local evaluation).",
  );
  // eslint-disable-next-line no-process-exit -- refusing to run with insecure secrets
  process.exit(1);
}
