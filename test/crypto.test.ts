import { describe, it, expect } from "vitest";
import {
  sha256,
  hmacSha512,
  base58Encode,
  base58Decode,
  base64Encode,
  base64Decode,
  hexEncode,
  hexDecode,
  makeKeypair,
  signBytes,
  verifySignature,
  ed25519PubToX25519,
  ed25519SeedToX25519PrivateKey,
  deriveHdSeed,
  mnemonicToSeed,
  validateMnemonic,
  generateMnemonic,
  BIP39_WORDLIST,
} from "../src/crypto/index.js";
import { parseOct, formatOct, parseOu } from "../src/units/index.js";

describe("sha256", () => {
  it("produces correct digest for empty input", async () => {
    const hash = await sha256(new Uint8Array(0));
    expect(hexEncode(hash)).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
  });

  it("produces correct digest for 'abc'", async () => {
    const hash = await sha256(new TextEncoder().encode("abc"));
    expect(hexEncode(hash)).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  it("accepts string input", async () => {
    const hash = await sha256("abc");
    expect(hexEncode(hash)).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });
});

describe("base58", () => {
  it("encodes and decodes round-trip", () => {
    const original = new Uint8Array([1, 2, 3, 4, 5, 255]);
    const encoded = base58Encode(original);
    const decoded = base58Decode(encoded);
    expect(decoded).toEqual(original);
  });

  it("handles leading zero bytes", () => {
    const data = new Uint8Array([0, 0, 1, 2, 3]);
    const encoded = base58Encode(data);
    expect(encoded.startsWith("11")).toBe(true);
    expect(base58Decode(encoded)).toEqual(data);
  });

  it("produces correct address length for 32-byte sha256 hash", async () => {
    const pubkey = new Uint8Array(32).fill(1);
    const hash = await sha256(pubkey);
    let b58 = base58Encode(hash);
    while (b58.length < 44) b58 = "1" + b58;
    const address = "oct" + b58;
    expect(address.length).toBe(47);
    expect(address.startsWith("oct")).toBe(true);
  });
});

describe("base64", () => {
  it("encodes and decodes round-trip", () => {
    const data = new Uint8Array([72, 101, 108, 108, 111]);
    expect(new TextDecoder().decode(base64Decode(base64Encode(data)))).toBe("Hello");
  });

  it("handles empty input", () => {
    expect(base64Encode(new Uint8Array(0))).toBe("");
  });
});

describe("hex", () => {
  it("encodes and decodes round-trip", () => {
    const data = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    expect(hexEncode(data)).toBe("deadbeef");
    expect(hexDecode("deadbeef")).toEqual(data);
  });
});

describe("makeKeypair", () => {
  it("produces a 32-byte secret key (seed)", async () => {
    const seed = new Uint8Array(32).fill(42);
    const kp = await makeKeypair(seed);
    expect(kp.secretKey.length).toBe(32);
    expect(kp.publicKey.length).toBe(32);
    expect(kp.address.length).toBe(47);
    expect(kp.address.startsWith("oct")).toBe(true);
  });

  it("produces deterministic output for the same seed", async () => {
    const seed = new Uint8Array(32).fill(99);
    const kp1 = await makeKeypair(seed);
    const kp2 = await makeKeypair(seed);
    expect(kp1.address).toBe(kp2.address);
    expect(hexEncode(kp1.publicKey)).toBe(hexEncode(kp2.publicKey));
  });
});

describe("signBytes / verifySignature", () => {
  it("produces a verifiable 64-byte signature", async () => {
    const seed = new Uint8Array(32).fill(7);
    const kp = await makeKeypair(seed);
    const msg = new TextEncoder().encode("hello octra");

    const sig = await signBytes(msg, kp.signingKey);
    expect(sig.length).toBe(64);

    const valid = await verifySignature(msg, sig, kp.publicKey);
    expect(valid).toBe(true);
  });

  it("rejects a tampered message", async () => {
    const seed = new Uint8Array(32).fill(7);
    const kp = await makeKeypair(seed);
    const msg = new TextEncoder().encode("hello octra");
    const sig = await signBytes(msg, kp.signingKey);

    const tampered = new TextEncoder().encode("hello octrb");
    const valid = await verifySignature(tampered, sig, kp.publicKey);
    expect(valid).toBe(false);
  });
});

describe("deriveHdSeed", () => {
  it("v1 index 0 is HMAC-derived (not a raw slice of master seed)", async () => {
    const master = new Uint8Array(64);
    for (let i = 0; i < 64; i++) master[i] = i;
    const child = await deriveHdSeed(master, 0, 1);
    expect(child.length).toBe(32);
    expect(child).not.toEqual(master.slice(0, 32));
  });

  it("v2 index 0 returns HMAC result (not first 32 bytes)", async () => {
    const master = new Uint8Array(64);
    for (let i = 0; i < 64; i++) master[i] = i;
    const childV2 = await deriveHdSeed(master, 0, 2);
    expect(childV2).not.toEqual(master.slice(0, 32));
    expect(childV2.length).toBe(32);
  });

  it("v1 index > 0 uses HMAC (different from index 0)", async () => {
    const master = new Uint8Array(64).fill(1);
    const child0 = await deriveHdSeed(master, 0, 1);
    const child1 = await deriveHdSeed(master, 1, 1);
    expect(hexEncode(child0)).not.toBe(hexEncode(child1));
  });

  it("v2 index > 0 produces different result than index 0", async () => {
    const master = new Uint8Array(64).fill(5);
    const child0 = await deriveHdSeed(master, 0, 2);
    const child1 = await deriveHdSeed(master, 1, 2);
    expect(hexEncode(child0)).not.toBe(hexEncode(child1));
  });

  it("is deterministic", async () => {
    const master = new Uint8Array(64).fill(22);
    const a = await deriveHdSeed(master, 3, 2);
    const b = await deriveHdSeed(master, 3, 2);
    expect(hexEncode(a)).toBe(hexEncode(b));
  });
});

describe("mnemonic", () => {
  it("BIP39_WORDLIST has 2048 words", () => {
    expect(BIP39_WORDLIST.length).toBe(2048);
  });

  it("generateMnemonic produces a valid 12-word mnemonic", async () => {
    const mnemonic = await generateMnemonic();
    const words = mnemonic.split(" ");
    expect(words.length).toBe(12);
    expect(await validateMnemonic(mnemonic)).toBe(true);
  });

  it("validateMnemonic rejects invalid words", async () => {
    expect(await validateMnemonic("invalidword one two three four five six seven eight nine ten eleven")).toBe(false);
  });

  it("validateMnemonic rejects wrong word count", async () => {
    expect(await validateMnemonic("abandon ability able about above absent absorb abstract absurd abuse access")).toBe(false);
  });

  it("validateMnemonic rejects a mnemonic with bad checksum", async () => {
    // All "abandon" (index 0) → entropy = 16 zero bytes, checksum must be 0011 ("about"), not 0000 ("abandon")
    expect(await validateMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon")).toBe(false);
  });

  it("validateMnemonic accepts the canonical BIP39 test vector", async () => {
    // entropy = 16 zero bytes, checksum = 0011 → last word is "about" (index 3)
    expect(await validateMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")).toBe(true);
  });

  it("mnemonicToSeed produces 64 bytes", async () => {
    const seed = await mnemonicToSeed("abandon ability able about above absent absorb abstract absurd abuse access accident");
    expect(seed.length).toBe(64);
  });

  it("mnemonicToSeed is deterministic", async () => {
    const mnemonic = "abandon ability able about above absent absorb abstract absurd abuse access accident";
    const s1 = await mnemonicToSeed(mnemonic);
    const s2 = await mnemonicToSeed(mnemonic);
    expect(hexEncode(s1)).toBe(hexEncode(s2));
  });
});

describe("ed25519PubToX25519", () => {
  it("returns 32 bytes", async () => {
    const seed = new Uint8Array(32).fill(3);
    const kp = await makeKeypair(seed);
    const x25519Pub = ed25519PubToX25519(kp.publicKey);
    expect(x25519Pub.length).toBe(32);
  });

  it("is deterministic", async () => {
    const seed = new Uint8Array(32).fill(3);
    const kp = await makeKeypair(seed);
    const a = ed25519PubToX25519(kp.publicKey);
    const b = ed25519PubToX25519(kp.publicKey);
    expect(hexEncode(a)).toBe(hexEncode(b));
  });
});

describe("ed25519SeedToX25519PrivateKey", () => {
  it("returns a clamped 32-byte key", async () => {
    const seed = new Uint8Array(32).fill(5);
    const xPriv = await ed25519SeedToX25519PrivateKey(seed);
    expect(xPriv.length).toBe(32);
    expect(xPriv[0]! & 7).toBe(0);
    expect(xPriv[31]! & 64).toBe(64);
    expect(xPriv[31]! & 128).toBe(0);
  });
});

describe("parseOct / formatOct", () => {
  it("parses integer amounts", () => {
    expect(parseOct("1")).toBe(1_000_000n);
    expect(parseOct("5")).toBe(5_000_000n);
  });

  it("parses decimal amounts", () => {
    expect(parseOct("1.5")).toBe(1_500_000n);
    expect(parseOct("0.000001")).toBe(1n);
    expect(parseOct("12.500000")).toBe(12_500_000n);
  });

  it("formats raw amounts to human strings", () => {
    expect(formatOct(1_000_000n)).toBe("1");
    expect(formatOct(1_500_000n)).toBe("1.5");
    expect(formatOct(1n)).toBe("0.000001");
    expect(formatOct(12_500_000n)).toBe("12.5");
  });

  it("round-trips through parse and format", () => {
    const amounts = ["0", "1", "1.5", "0.000001", "100.123456", "999999"];
    for (const a of amounts) {
      const raw = parseOct(a);
      const formatted = formatOct(raw);
      expect(parseOct(formatted)).toBe(raw);
    }
  });
});

describe("parseOu", () => {
  it("accepts valid integer strings", () => {
    expect(parseOu("200000")).toBe("200000");
    expect(parseOu("0")).toBe("0");
  });

  it("rejects non-integer strings", () => {
    expect(() => parseOu("1.5")).toThrow();
    expect(() => parseOu("abc")).toThrow();
  });
});

describe("parseOct excess-precision", () => {
  it("rejects more than 6 fractional digits instead of silently truncating", () => {
    expect(() => parseOct("1.1234567")).toThrow(/fractional digits/);
    // 6 digits is fine
    expect(parseOct("1.123456")).toBe(1_123_456n);
  });
});

describe("parseToken excess-precision", () => {
  it("rejects more fractional digits than allowed", async () => {
    const { parseToken } = await import("../src/units/oct.js");
    expect(() => parseToken("1.123", 2)).toThrow(/fractional digits/);
    expect(parseToken("1.12", 2)).toBe(112n);
  });
});

describe("24-word mnemonic", () => {
  it("generateMnemonic(256) produces 24 valid words", async () => {
    const { generateMnemonic } = await import("../src/crypto/index.js");
    const m = await generateMnemonic(256);
    expect(m.split(" ").length).toBe(24);
    expect(await validateMnemonic(m)).toBe(true);
  });

  it("generateMnemonic() default still emits 12 words", async () => {
    const { generateMnemonic } = await import("../src/crypto/index.js");
    const m = await generateMnemonic();
    expect(m.split(" ").length).toBe(12);
    expect(await validateMnemonic(m)).toBe(true);
  });

  it("rejects invalid strength values", async () => {
    const { generateMnemonic } = await import("../src/crypto/index.js");
    // @ts-expect-error testing runtime guard
    await expect(generateMnemonic(100)).rejects.toThrow();
  });
});

describe("validateAddressFormat", () => {
  it("accepts a freshly derived address", async () => {
    const { validateAddressFormat } = await import("../src/crypto/index.js");
    const seed = new Uint8Array(32).fill(1);
    const kp = await makeKeypair(seed);
    expect(validateAddressFormat(kp.address)).toBe(true);
  });

  it("rejects bad prefix", async () => {
    const { validateAddressFormat } = await import("../src/crypto/index.js");
    expect(validateAddressFormat("xyz" + "1".repeat(44))).toBe(false);
  });

  it("rejects wrong length", async () => {
    const { validateAddressFormat } = await import("../src/crypto/index.js");
    expect(validateAddressFormat("oct" + "1".repeat(43))).toBe(false);
    expect(validateAddressFormat("oct" + "1".repeat(45))).toBe(false);
  });

  it("rejects characters outside the base58 alphabet", async () => {
    const { validateAddressFormat } = await import("../src/crypto/index.js");
    // 'O' (uppercase O) and '0' are excluded from base58
    expect(validateAddressFormat("oct" + "O".repeat(44))).toBe(false);
    expect(validateAddressFormat("oct" + "0".repeat(44))).toBe(false);
  });

  it("accepts addresses whose hash has natural base58 length < 44 (padded form)", async () => {
    // Regression: ~5.8% of sha256 hashes are < 58^43, so deriveAddress pads with a leading
    // "1" to reach 44 chars. The earlier validator decoded the body and rejected anything
    // whose decoded length exceeded 32, which rejected this entire ~1-in-17 slice of
    // legitimately derived addresses.
    const { validateAddressFormat } = await import("../src/crypto/index.js");
    const { base58Encode } = await import("../src/crypto/encoding.js");
    const hash = new Uint8Array(32);
    hash[0] = 0x08; // hash value just below 2^252, so natural base58 length is 43
    let b58 = base58Encode(hash);
    while (b58.length < 44) b58 = "1" + b58;
    expect(b58.length).toBe(44);
    expect(validateAddressFormat("oct" + b58)).toBe(true);
  });
});
