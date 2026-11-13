import { describe, expect, it, vi } from "vitest";

vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), error: vi.fn(), warn: vi.fn(), debug: vi.fn() },
}));

import { describeUpstreamError } from "./mcp-proxy";

describe("describeUpstreamError", () => {
  it("appends the HTTP status when the message lacks it", () => {
    const msg = describeUpstreamError({
      message:
        'Streamable HTTP error: Error POSTing to endpoint: {"error":{"message":"Missing or invalid access token."}}',
      code: 401,
    });
    expect(msg).toContain("401");
    expect(msg).toMatch(/\(HTTP 401\)$/);
  });

  it("leaves the message alone when it already mentions the status", () => {
    const message = "Error POSTing to endpoint (HTTP 404): nope";
    expect(describeUpstreamError({ message, code: 404 })).toBe(message);
  });

  it("ignores non-HTTP codes and missing codes", () => {
    expect(describeUpstreamError({ message: "boom", code: -32001 })).toBe(
      "boom",
    );
    expect(
      describeUpstreamError({ message: "boom", code: "ECONNREFUSED" }),
    ).toBe("boom");
    expect(describeUpstreamError({ message: "boom" })).toBe("boom");
  });
});
