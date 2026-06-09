import { describe, it, expect } from "vitest";
import { OctUri } from "../src/circle/uri.js";
import { deriveReadKey, computeResourceKey, sealAsset, unsealAsset } from "../src/circle/sealer.js";
import { computeCircleId } from "../src/circle/circle.js";
import type { CircleDeployConfig } from "../src/circle/circle.js";

// --- OctUri ---

describe("OctUri", () => {
  it("constructs with circleId and default path", () => {
    const uri = new OctUri("octABC123", );
    expect(uri.circleId).toBe("octABC123");
    expect(uri.path).toBe("/index.html");
    expect(uri.toString()).toBe("oct://octABC123/index.html");
  });

  it("normalizes path without leading slash", () => {
    const uri = new OctUri("octABC123", "app/main.js");
    expect(uri.path).toBe("/app/main.js");
  });

  it("parses oct:// URI with path", () => {
    const uri = OctUri.parse("oct://octXYZ999/static/style.css");
    expect(uri.circleId).toBe("octXYZ999");
    expect(uri.path).toBe("/static/style.css");
    expect(uri.toString()).toBe("oct://octXYZ999/static/style.css");
  });

  it("parses oct:// URI without path → /index.html", () => {
    const uri = OctUri.parse("oct://octXYZ999");
    expect(uri.path).toBe("/index.html");
  });

  it("throws on invalid scheme", () => {
    expect(() => OctUri.parse("https://example.com")).toThrow("Invalid oct://");
  });
});

// --- sealer ---

const CIRCLE_ID = "octTestCircle000000000000000000000000000000000";
const KEY_ID = "default";
const PASSPHRASE = "super-secret-pass";

describe("deriveReadKey", () => {
  it("returns a 32-byte key", async () => {
    const key = await deriveReadKey(CIRCLE_ID, KEY_ID, PASSPHRASE);
    expect(key).toBeInstanceOf(Uint8Array);
    expect(key.length).toBe(32);
  });

  it("is deterministic", async () => {
    const k1 = await deriveReadKey(CIRCLE_ID, KEY_ID, PASSPHRASE);
    const k2 = await deriveReadKey(CIRCLE_ID, KEY_ID, PASSPHRASE);
    expect(k1).toEqual(k2);
  });

  it("differs for different passphrases", async () => {
    const k1 = await deriveReadKey(CIRCLE_ID, KEY_ID, PASSPHRASE);
    const k2 = await deriveReadKey(CIRCLE_ID, KEY_ID, "other-pass");
    expect(k1).not.toEqual(k2);
  });

  it("differs for different key IDs", async () => {
    const k1 = await deriveReadKey(CIRCLE_ID, "default", PASSPHRASE);
    const k2 = await deriveReadKey(CIRCLE_ID, "secondary", PASSPHRASE);
    expect(k1).not.toEqual(k2);
  });
});

describe("computeResourceKey", () => {
  it("returns a 64-char hex string", async () => {
    const key = await computeResourceKey(CIRCLE_ID, "/index.html");
    expect(key).toMatch(/^[0-9a-f]{64}$/);
  });

  it("is deterministic", async () => {
    const k1 = await computeResourceKey(CIRCLE_ID, "/index.html");
    const k2 = await computeResourceKey(CIRCLE_ID, "/index.html");
    expect(k1).toBe(k2);
  });

  it("normalizes missing leading slash", async () => {
    const k1 = await computeResourceKey(CIRCLE_ID, "/index.html");
    const k2 = await computeResourceKey(CIRCLE_ID, "index.html");
    expect(k1).toBe(k2);
  });

  it("differs for different paths", async () => {
    const k1 = await computeResourceKey(CIRCLE_ID, "/index.html");
    const k2 = await computeResourceKey(CIRCLE_ID, "/other.html");
    expect(k1).not.toBe(k2);
  });
});

describe("sealAsset / unsealAsset", () => {
  it("round-trips plaintext correctly", async () => {
    const plaintext = new TextEncoder().encode("Hello, Octra!");
    const key = await deriveReadKey(CIRCLE_ID, KEY_ID, PASSPHRASE);
    const { ciphertext, plaintextHash } = await sealAsset(plaintext, key);

    expect(ciphertext.length).toBeGreaterThan(17 + 16);
    expect(plaintextHash).toMatch(/^[0-9a-f]{64}$/);

    const recovered = await unsealAsset(ciphertext, key, plaintextHash);
    expect(recovered).toEqual(plaintext);
  });

  it("OCRS1 magic header is present", async () => {
    const plaintext = new Uint8Array([1, 2, 3, 4, 5]);
    const key = await deriveReadKey(CIRCLE_ID, KEY_ID, PASSPHRASE);
    const { ciphertext } = await sealAsset(plaintext, key);
    const magic = new TextDecoder().decode(ciphertext.slice(0, 5));
    expect(magic).toBe("OCRS1");
  });

  it("rejects wrong key", async () => {
    const plaintext = new TextEncoder().encode("secret");
    const key = await deriveReadKey(CIRCLE_ID, KEY_ID, PASSPHRASE);
    const wrongKey = await deriveReadKey(CIRCLE_ID, KEY_ID, "wrong-pass");
    const { ciphertext } = await sealAsset(plaintext, key);
    await expect(unsealAsset(ciphertext, wrongKey)).rejects.toThrow("Decryption failed");
  });

  it("rejects hash mismatch", async () => {
    const plaintext = new TextEncoder().encode("tamper test");
    const key = await deriveReadKey(CIRCLE_ID, KEY_ID, PASSPHRASE);
    const { ciphertext } = await sealAsset(plaintext, key);
    await expect(unsealAsset(ciphertext, key, "a".repeat(64))).rejects.toThrow("hash mismatch");
  });

  it("padding class 4k expands ciphertext", async () => {
    const small = new TextEncoder().encode("tiny");
    const key = await deriveReadKey(CIRCLE_ID, KEY_ID, PASSPHRASE);
    const { ciphertext: unpadded } = await sealAsset(small, key);
    const { ciphertext: padded } = await sealAsset(small, key, "4k");
    expect(padded.length).toBeGreaterThan(unpadded.length);
    // 5(magic) + 12(nonce) + 4096(frame) + 16(tag) = 4129 minimum
    expect(padded.length).toBeGreaterThanOrEqual(5 + 12 + 4096 + 16);
  });

  it("padding class round-trips correctly", async () => {
    const plaintext = new TextEncoder().encode("padded content");
    const key = await deriveReadKey(CIRCLE_ID, KEY_ID, PASSPHRASE);
    const { ciphertext, plaintextHash } = await sealAsset(plaintext, key, "16k");
    const recovered = await unsealAsset(ciphertext, key, plaintextHash);
    expect(recovered).toEqual(plaintext);
  });
});

// --- computeCircleId ---

describe("computeCircleId", () => {
  const config: CircleDeployConfig = {
    runtime: "octb",
    privacyClass: "sealed",
    browserMode: "native_sealed",
    resourceMode: "sealed_read",
  };

  it("returns an oct-prefixed 47-char string", async () => {
    const id = await computeCircleId("octDeployer00000000000000000000000000000000000", 1, config);
    expect(id.startsWith("oct")).toBe(true);
    expect(id.length).toBe(47);
  });

  it("is deterministic", async () => {
    const deployer = "octDeployer00000000000000000000000000000000000";
    const id1 = await computeCircleId(deployer, 1, config);
    const id2 = await computeCircleId(deployer, 1, config);
    expect(id1).toBe(id2);
  });

  it("changes with different nonce", async () => {
    const deployer = "octDeployer00000000000000000000000000000000000";
    const id1 = await computeCircleId(deployer, 1, config);
    const id2 = await computeCircleId(deployer, 2, config);
    expect(id1).not.toBe(id2);
  });

  it("changes with different deployer", async () => {
    const id1 = await computeCircleId("octDeployer00000000000000000000000000000000000", 1, config);
    const id2 = await computeCircleId("octDeployer11111111111111111111111111111111111", 1, config);
    expect(id1).not.toBe(id2);
  });

  it("changes with different config", async () => {
    const deployer = "octDeployer00000000000000000000000000000000000";
    const altConfig: CircleDeployConfig = { ...config, runtime: "wasm" };
    const id1 = await computeCircleId(deployer, 1, config);
    const id2 = await computeCircleId(deployer, 1, altConfig);
    expect(id1).not.toBe(id2);
  });
});
