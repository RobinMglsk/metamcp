import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  kcwAuthRateLimiter,
  requireKcwServiceToken,
} from "./kcw-service-token.middleware";

const TOKEN = "t".repeat(40);

const run = (authorization?: string, ip = "10.0.0.1") => {
  const res = {
    status: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
  };
  const next = vi.fn();
  requireKcwServiceToken(
    { headers: { authorization }, ip } as never,
    res as never,
    next,
  );
  return { res, next };
};

beforeEach(() => {
  vi.stubEnv("KCW_SERVICE_TOKEN", TOKEN);
  kcwAuthRateLimiter.cleanup();
});
afterEach(() => vi.unstubAllEnvs());

describe("requireKcwServiceToken", () => {
  it("answers 404 when the feature is off", () => {
    vi.stubEnv("KCW_SERVICE_TOKEN", "");
    const { res, next } = run(`Bearer ${TOKEN}`);
    expect(res.status).toHaveBeenCalledWith(404);
    expect(next).not.toHaveBeenCalled();
  });

  it("passes the right token", () => {
    const { next } = run(`Bearer ${TOKEN}`);
    expect(next).toHaveBeenCalled();
  });

  it.each([undefined, "", "Bearer ", "Bearer nope", `Basic ${TOKEN}`, TOKEN])(
    "refuses %s with 401",
    (header) => {
      const { res, next } = run(header, `10.1.0.${Math.random()}`);
      expect(res.status).toHaveBeenCalledWith(401);
      expect(next).not.toHaveBeenCalled();
    },
  );

  it("rate limits repeated failures per client", () => {
    let last = run("Bearer bad", "10.0.0.3");
    for (let i = 0; i < 12; i++) last = run("Bearer bad", "10.0.0.3");
    expect(last.res.status).toHaveBeenCalledWith(429);
    expect(run("Bearer bad", "10.0.0.4").res.status).toHaveBeenCalledWith(401);
  });
});
