import { beforeEach, describe, expect, it, vi } from "vitest";

const handler = vi.hoisted(() => vi.fn());
vi.mock("../auth", () => ({ auth: { handler } }));

import { getSessionFromRequest } from "./session-check";

const req = (headers: Record<string, string>) => ({ headers }) as never;

beforeEach(() => {
  vi.clearAllMocks();
  process.env.APP_URL = "http://app.test:12008";
  handler.mockResolvedValue(
    new Response(JSON.stringify({ user: { id: "u" }, session: { id: "s" } })),
  );
});

describe("getSessionFromRequest", () => {
  it("returns an empty session without calling auth when there is no cookie", async () => {
    expect(await getSessionFromRequest(req({}))).toEqual({});
    expect(handler).not.toHaveBeenCalled();
  });

  it("ignores a malformed Host header and builds the URL from APP_URL", async () => {
    const out = await getSessionFromRequest(
      req({ cookie: "a=b", host: "bad host/..:x" }),
    );
    expect(out.user).toEqual({ id: "u" });
    expect(handler.mock.calls[0][0].url).toBe(
      "http://app.test:12008/api/auth/get-session",
    );
  });

  it("requires both user and session", async () => {
    handler.mockResolvedValue(
      new Response(JSON.stringify({ user: { id: "u" } })),
    );
    expect(await getSessionFromRequest(req({ cookie: "a=b" }))).toEqual({});
  });
});
