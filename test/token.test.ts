import { describe, it, expect } from "vitest";
import { parseToken, formatToken } from "../src/token/ocs01.js";

describe("parseToken", () => {
  it("parses integer amount", () => {
    expect(parseToken("100", 6)).toBe(100_000_000n);
  });

  it("parses fractional amount", () => {
    expect(parseToken("1.5", 6)).toBe(1_500_000n);
  });

  it("parses zero", () => {
    expect(parseToken("0", 6)).toBe(0n);
  });

  it("parses amount with fewer decimal places than precision", () => {
    expect(parseToken("1.5", 8)).toBe(150_000_000n);
  });

  it("parses amount with exact decimal precision", () => {
    expect(parseToken("1.000001", 6)).toBe(1_000_001n);
  });

  it("truncates extra decimal places", () => {
    expect(parseToken("1.1234567", 6)).toBe(1_123_456n);
  });

  it("throws on invalid input", () => {
    expect(() => parseToken("abc", 6)).toThrow("Invalid token amount");
    expect(() => parseToken("1.2.3", 6)).toThrow("Invalid token amount");
    expect(() => parseToken("-1", 6)).toThrow("Invalid token amount");
  });
});

describe("formatToken", () => {
  it("formats integer amount", () => {
    expect(formatToken(100_000_000n, 6)).toBe("100");
  });

  it("formats fractional amount", () => {
    expect(formatToken(1_500_000n, 6)).toBe("1.5");
  });

  it("formats zero", () => {
    expect(formatToken(0n, 6)).toBe("0");
  });

  it("formats negative amount", () => {
    expect(formatToken(-1_000_000n, 6)).toBe("-1");
  });

  it("strips trailing zeros", () => {
    expect(formatToken(1_100_000n, 6)).toBe("1.1");
  });

  it("preserves significant digits", () => {
    expect(formatToken(1_000_001n, 6)).toBe("1.000001");
  });

  it("round-trips with parseToken", () => {
    const amounts = ["0", "1", "1.5", "100.123456", "999999.000001"];
    for (const a of amounts) {
      expect(formatToken(parseToken(a, 6), 6)).toBe(a);
    }
  });
});
