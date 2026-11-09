import { describe, expect, it, vi } from "vitest";

import { isLinkLocalOrMetadataAddress } from "./host-ranges";
import {
  assertOutboundUrlAllowed,
  createGuardedFetch,
  OutboundUrlError,
  type Resolver,
} from "./ssrf-guard";

const resolveTo =
  (...addresses: string[]): Resolver =>
  async () =>
    addresses;
const PUBLIC = { allowPrivate: false };
const INTERNAL = { allowPrivate: true };

describe("isLinkLocalOrMetadataAddress", () => {
  it.each([
    "169.254.169.254",
    "169.254.0.1",
    "100.100.100.200",
    "168.63.129.16",
    "fe80::1",
    "::ffff:169.254.169.254",
    "::ffff:a9fe:a9fe",
    "fd00:ec2::254",
  ])("flags %s", (ip) => expect(isLinkLocalOrMetadataAddress(ip)).toBe(true));

  it.each(["8.8.8.8", "10.0.0.1", "127.0.0.1", "169.253.1.1", "2606:4700::1"])(
    "does not flag %s",
    (ip) => expect(isLinkLocalOrMetadataAddress(ip)).toBe(false),
  );
});

describe("assertOutboundUrlAllowed", () => {
  it("accepts public hosts", async () => {
    await expect(
      assertOutboundUrlAllowed(
        "https://mcp.example.com/sse",
        PUBLIC,
        resolveTo("93.184.216.34"),
      ),
    ).resolves.toBeInstanceOf(URL);
  });

  it("rejects non-http schemes, bad URLs and embedded credentials", async () => {
    for (const u of [
      "file:///etc/passwd",
      "ftp://a.example/x",
      "gopher://a/",
      "not a url",
      "https://user:pw@a.example/x",
    ]) {
      await expect(
        assertOutboundUrlAllowed(u, INTERNAL, resolveTo("93.184.216.34")),
      ).rejects.toBeInstanceOf(OutboundUrlError);
    }
  });

  it("refuses metadata/link-local targets for everyone", async () => {
    for (const policy of [PUBLIC, INTERNAL]) {
      for (const u of [
        "http://169.254.169.254/latest/meta-data/",
        "http://[fe80::1]/",
        "http://[::ffff:169.254.169.254]/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://100.100.100.200/",
      ]) {
        await expect(
          assertOutboundUrlAllowed(u, policy, resolveTo("93.184.216.34")),
        ).rejects.toThrow(OutboundUrlError);
      }
    }
  });

  it("refuses a hostname that resolves to a metadata address (DNS)", async () => {
    await expect(
      assertOutboundUrlAllowed(
        "https://evil.example/x",
        INTERNAL,
        resolveTo("93.184.216.34", "169.254.169.254"),
      ),
    ).rejects.toThrow(/link-local|metadata/);
  });

  it("private/loopback targets depend on the policy", async () => {
    for (const u of [
      "http://127.0.0.1:8080/",
      "http://localhost/",
      "http://10.0.0.5/",
      "http://[::1]/",
      "http://svc.internal/",
    ]) {
      await expect(
        assertOutboundUrlAllowed(u, PUBLIC, resolveTo("10.0.0.5")),
      ).rejects.toThrow(/private/);
      await expect(
        assertOutboundUrlAllowed(u, INTERNAL, resolveTo("10.0.0.5")),
      ).resolves.toBeInstanceOf(URL);
    }
    await expect(
      assertOutboundUrlAllowed(
        "https://rebind.example/",
        PUBLIC,
        resolveTo("127.0.0.1"),
      ),
    ).rejects.toThrow(/private/);
  });

  it("reports unresolvable hosts", async () => {
    const failing: Resolver = async () => {
      throw new Error("ENOTFOUND");
    };
    await expect(
      assertOutboundUrlAllowed("https://nope.example/", PUBLIC, failing),
    ).rejects.toThrow(/could not be resolved/);
  });
});

describe("createGuardedFetch", () => {
  const ok = () => new Response("ok", { status: 200 });
  const redirect = (to: string, status = 302) =>
    new Response(null, { status, headers: { location: to } });

  it("passes allowed requests through with redirect handled manually", async () => {
    const base = vi.fn().mockResolvedValue(ok());
    const f = createGuardedFetch(PUBLIC, base, resolveTo("93.184.216.34"));
    const r = await f("https://a.example/x", { method: "POST", body: "b" });
    expect(r.status).toBe(200);
    expect(base).toHaveBeenCalledWith(
      "https://a.example/x",
      expect.objectContaining({ redirect: "manual", method: "POST" }),
    );
  });

  it("blocks a redirect to the metadata service", async () => {
    const base = vi
      .fn()
      .mockResolvedValueOnce(
        redirect("http://169.254.169.254/latest/meta-data/"),
      );
    const f = createGuardedFetch(INTERNAL, base, resolveTo("93.184.216.34"));
    await expect(f("https://a.example/x")).rejects.toThrow(OutboundUrlError);
    expect(base).toHaveBeenCalledTimes(1);
  });

  it("follows allowed redirects (relative and absolute) and turns 303 into GET", async () => {
    const base = vi
      .fn()
      .mockResolvedValueOnce(redirect("/next", 303))
      .mockResolvedValueOnce(redirect("https://b.example/final", 302))
      .mockResolvedValueOnce(ok());
    const f = createGuardedFetch(PUBLIC, base, resolveTo("93.184.216.34"));
    const r = await f("https://a.example/start", {
      method: "POST",
      body: "secret",
    });
    expect(r.status).toBe(200);
    expect(base.mock.calls.map((c) => c[0])).toEqual([
      "https://a.example/start",
      "https://a.example/next",
      "https://b.example/final",
    ]);
    expect(base.mock.calls[1][1]).toMatchObject({
      method: "GET",
      body: undefined,
    });
  });

  it("stops after too many redirects", async () => {
    const base = vi
      .fn()
      .mockImplementation(async () => redirect("https://a.example/loop"));
    const f = createGuardedFetch(PUBLIC, base, resolveTo("93.184.216.34"));
    await expect(f("https://a.example/loop")).rejects.toThrow(
      /Too many redirects/,
    );
  });

  it("re-validates DNS on every request", async () => {
    let calls = 0;
    const resolver: Resolver = async () =>
      ++calls === 1 ? ["93.184.216.34"] : ["169.254.169.254"];
    const base = vi.fn().mockResolvedValue(ok());
    const f = createGuardedFetch(INTERNAL, base, resolver);
    await f("https://a.example/x");
    await expect(f("https://a.example/x")).rejects.toThrow(OutboundUrlError);
  });
});
