import { describe, it, expect } from "vitest";
import { Wallet } from "../src/wallet/wallet.js";
import { hexEncode, base64Decode, verifySignature } from "../src/crypto/index.js";

// Canonical BIP39 test vector: entropy = 16 zero bytes, checksum = 0011 → last word "about"
const TEST_MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

describe("Wallet.fromMnemonic", () => {
  it("derives a valid address from a known mnemonic (v1)", async () => {
    const wallet = await Wallet.fromMnemonic(TEST_MNEMONIC, 1);
    expect(wallet.address.length).toBe(47);
    expect(wallet.address.startsWith("oct")).toBe(true);
    expect(wallet.hdVersion).toBe(1);
    expect(wallet.hdIndex).toBe(0);
  });

  it("v2 produces a different address than v1", async () => {
    const walletV1 = await Wallet.fromMnemonic(TEST_MNEMONIC, 1);
    const walletV2 = await Wallet.fromMnemonic(TEST_MNEMONIC, 2);
    expect(walletV1.address).not.toBe(walletV2.address);
  });

  it("is deterministic for the same mnemonic and version", async () => {
    const w1 = await Wallet.fromMnemonic(TEST_MNEMONIC, 1);
    const w2 = await Wallet.fromMnemonic(TEST_MNEMONIC, 1);
    expect(w1.address).toBe(w2.address);
    expect(hexEncode(w1.keypair.publicKey)).toBe(hexEncode(w2.keypair.publicKey));
  });

  it("rejects an invalid mnemonic", async () => {
    await expect(Wallet.fromMnemonic("not a valid mnemonic")).rejects.toThrow();
  });

  it("stores the mnemonic", async () => {
    const w = await Wallet.fromMnemonic(TEST_MNEMONIC, 1);
    expect(w.mnemonic).toBe(TEST_MNEMONIC);
  });
});

describe("Wallet.fromPrivateKey", () => {
  it("imports a base64 private key and produces the same address", async () => {
    const original = await Wallet.fromMnemonic(TEST_MNEMONIC, 1);
    const imported = await Wallet.fromPrivateKey(original.privateKeyBase64);
    expect(imported.address).toBe(original.address);
  });

  it("accepts a 64-byte seed||pub form when pub matches seed", async () => {
    const original = await Wallet.fromMnemonic(TEST_MNEMONIC, 1);
    const { base64Encode } = await import("../src/crypto/encoding.js");
    const combined = new Uint8Array(64);
    combined.set(original.keypair.secretKey, 0);
    combined.set(original.keypair.publicKey, 32);
    const imported = await Wallet.fromPrivateKey(base64Encode(combined));
    expect(imported.address).toBe(original.address);
  });

  it("rejects 64-byte form when pub does not match seed", async () => {
    const original = await Wallet.fromMnemonic(TEST_MNEMONIC, 1);
    const { base64Encode } = await import("../src/crypto/encoding.js");
    const combined = new Uint8Array(64);
    combined.set(original.keypair.secretKey, 0);
    // Wrong pub (all 0xFF).
    combined.set(new Uint8Array(32).fill(0xff), 32);
    await expect(Wallet.fromPrivateKey(base64Encode(combined))).rejects.toThrow(/public-half/);
  });

  it("rejects byte lengths other than 32 or 64", async () => {
    const { base64Encode } = await import("../src/crypto/encoding.js");
    // 31 bytes
    await expect(
      Wallet.fromPrivateKey(base64Encode(new Uint8Array(31))),
    ).rejects.toThrow(/32 bytes/);
    // 48 bytes
    await expect(
      Wallet.fromPrivateKey(base64Encode(new Uint8Array(48))),
    ).rejects.toThrow(/32 bytes/);
    // 65 bytes
    await expect(
      Wallet.fromPrivateKey(base64Encode(new Uint8Array(65))),
    ).rejects.toThrow(/32 bytes/);
  });
});

describe("Wallet.generate", () => {
  it("creates a fresh wallet with unique address", async () => {
    const w1 = await Wallet.generate();
    const w2 = await Wallet.generate();
    expect(w1.address.startsWith("oct")).toBe(true);
    expect(w1.address.length).toBe(47);
    expect(w1.address).not.toBe(w2.address);
    expect(w1.mnemonic).toBeDefined();
    expect(w1.hdVersion).toBe(2);
  });
});

describe("Wallet signing", () => {
  it("sign() produces a valid Ed25519 signature", async () => {
    const wallet = await Wallet.fromMnemonic(TEST_MNEMONIC, 1);
    const msg = new TextEncoder().encode("test message for signing");
    const sig = await wallet.sign(msg);
    expect(sig.length).toBe(64);
    const valid = await verifySignature(msg, sig, wallet.keypair.publicKey);
    expect(valid).toBe(true);
  });
});

describe("Wallet HD derivation", () => {
  it("derives different accounts for different indices", async () => {
    const root = await Wallet.fromMnemonic(TEST_MNEMONIC, 2, 0);
    const acc1 = await root.deriveHdAccount(1);
    const acc2 = await root.deriveHdAccount(2);
    expect(acc1.address).not.toBe(root.address);
    expect(acc2.address).not.toBe(acc1.address);
  });

  it("fails without a master seed", async () => {
    const w = await Wallet.fromPrivateKey(
      (await Wallet.fromMnemonic(TEST_MNEMONIC, 1)).privateKeyBase64,
    );
    await expect(w.deriveHdAccount(1)).rejects.toThrow();
  });
});

describe("Wallet keystore round-trip", () => {
  it("encrypts and decrypts with the correct PIN", async () => {
    const wallet = await Wallet.fromMnemonic(TEST_MNEMONIC, 2);
    const pin = "testpin1234";
    const keystore = await wallet.toKeystore(pin);
    expect(keystore.length).toBeGreaterThan(60);

    const loaded = await Wallet.fromKeystore(keystore, pin);
    expect(loaded.address).toBe(wallet.address);
    expect(hexEncode(loaded.keypair.publicKey)).toBe(hexEncode(wallet.keypair.publicKey));
  });

  it("fails with wrong PIN", async () => {
    const wallet = await Wallet.fromMnemonic(TEST_MNEMONIC, 2);
    const keystore = await wallet.toKeystore("correctpin");
    await expect(Wallet.fromKeystore(keystore, "wrongpin")).rejects.toThrow();
  });

  it("preserves master seed and mnemonic through keystore", async () => {
    const wallet = await Wallet.fromMnemonic(TEST_MNEMONIC, 2);
    const keystore = await wallet.toKeystore("pin");
    const loaded = await Wallet.fromKeystore(keystore, "pin");
    expect(loaded.mnemonic).toBe(TEST_MNEMONIC);
    expect(loaded.hdVersion).toBe(2);
  });
});
