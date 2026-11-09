import { describe, expect, it } from "vitest";

import { isPrivateOrLocalHost } from "./host-ranges";

describe("isPrivateOrLocalHost", () => {
  it.each([
    "localhost",
    "LOCALHOST",
    "foo.localhost",
    "printer.local",
    "db.internal",
    "127.0.0.1",
    "127.1.2.3",
    "0.0.0.0",
    "10.0.0.1",
    "172.16.0.1",
    "172.31.255.255",
    "192.168.1.1",
    "169.254.169.254",
    "100.64.0.1",
    "224.0.0.1",
    "[::1]",
    "::",
    "fd00::1",
    "fc00::1",
    "fe80::1",
    "[::ffff:127.0.0.1]",
    "::ffff:7f00:1",
    "::ffff:a9fe:a9fe",
  ])("treats %s as private/local", (h) => {
    expect(isPrivateOrLocalHost(h)).toBe(true);
  });

  it.each([
    "example.com",
    "10.example.com",
    "172.example.org",
    "192.168.example.net",
    "8.8.8.8",
    "172.15.0.1",
    "172.32.0.1",
    "100.63.0.1",
    "169.253.0.1",
    "2606:4700:4700::1111",
    "::ffff:808:808",
  ])("treats %s as public", (h) => {
    expect(isPrivateOrLocalHost(h)).toBe(false);
  });

  it("matches what new URL() produces for obfuscated IPv4 forms", () => {
    for (const u of [
      "https://2130706433/cb",
      "https://0x7f.1/cb",
      "https://127.1/cb",
      "https://[::ffff:127.0.0.1]/cb",
    ]) {
      expect(isPrivateOrLocalHost(new URL(u).hostname)).toBe(true);
    }
  });
});
