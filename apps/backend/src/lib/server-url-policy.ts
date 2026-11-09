import { outboundPolicyForUser } from "./authz";
import { assertOutboundUrlAllowed, OutboundUrlError } from "./ssrf-guard";

/**
 * Checks the URL of an HTTP-based MCP server against the saving user's
 * outbound policy. Returns an error message, or null when the URL is fine
 * (or the server has no URL, e.g. STDIO).
 */
export async function checkMcpServerUrl(
  url: string | null | undefined,
  userId: string,
): Promise<string | null> {
  if (!url) return null;
  try {
    await assertOutboundUrlAllowed(url, await outboundPolicyForUser(userId));
    return null;
  } catch (error) {
    if (error instanceof OutboundUrlError) {
      return `Invalid server URL: ${error.message}`;
    }
    throw error;
  }
}
