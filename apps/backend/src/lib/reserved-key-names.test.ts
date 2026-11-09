import { describe, expect, it } from "vitest";

import {
  autoKeyName,
  isReservedKeyName,
  kcwSessionKeyName,
} from "./reserved-key-names";

describe("isReservedKeyName", () => {
  it("reserves endpoint auto keys and kcw session keys, case-insensitively", () => {
    expect(isReservedKeyName(autoKeyName("abc"))).toBe(true);
    expect(isReservedKeyName(kcwSessionKeyName("s1", "m1"))).toBe(true);
    expect(isReservedKeyName("  KCW-Session-anything")).toBe(true);
  });

  it("leaves ordinary names alone", () => {
    expect(isReservedKeyName("my key")).toBe(false);
    expect(isReservedKeyName("kcw")).toBe(false);
  });
});
