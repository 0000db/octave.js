import { describe, it, expect } from "vitest";
import {
  makeKeypair,
  signBytes,
  ed25519PubToX25519,
  ed25519SeedToX25519PrivateKey,
  mnemonicToSeed,
  hexEncode,
  hexDecode,
} from "../src/crypto/index.js";

// Known-answer vectors cross-verified against PyNaCl, Python `cryptography`,
// Node native crypto, and python-mnemonic. Any failure here means the SDK has
// drifted from these reference implementations.

describe("Ed25519 known-answer vectors", () => {
  it("seed 9d61… → expected pubkey and signature over empty message", async () => {
    const seed = hexDecode("9d61b19deffd5a60ba844af492ec2cc44449c1f7039acab23db66cbbb654d973");
    const kp = await makeKeypair(seed);
    expect(hexEncode(kp.publicKey)).toBe(
      "9bff8b08a338f1a09aa65f0d61a3a86b88acef872a71e0cf6cfc1b95f83e5fc8",
    );
    const sig = await signBytes(new Uint8Array(0), kp.signingKey);
    expect(hexEncode(sig)).toBe(
      "dae5cd655498a7f8e330225941d952065e9d6128d1842b8a63c39ee6fa19b0bc07a8c5481d5d672b4956cded57f70dd40480dda1fa261fc1be1ad0f3848fdb0b",
    );
  });

  it("RFC 8032 TV2: seed 4ccd… → pubkey and signature over 0x72", async () => {
    const seed = hexDecode("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
    const kp = await makeKeypair(seed);
    expect(hexEncode(kp.publicKey)).toBe(
      "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    );
    const sig = await signBytes(new Uint8Array([0x72]), kp.signingKey);
    expect(hexEncode(sig)).toBe(
      "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    );
  });
});

describe("BIP39 known-answer vectors", () => {
  it("Trezor zero-entropy mnemonic + TREZOR passphrase produces canonical 64-byte seed", async () => {
    const seed = await mnemonicToSeed(
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
      "TREZOR",
    );
    expect(hexEncode(seed)).toBe(
      "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
    );
  });

  it('"legal winner thank year…" + TREZOR produces python-mnemonic reference seed', async () => {
    const seed = await mnemonicToSeed(
      "legal winner thank year wave sausage worth useful legal winner thank yellow",
      "TREZOR",
    );
    expect(hexEncode(seed)).toBe(
      "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
    );
  });
});

describe("Ed25519→X25519 birational map", () => {
  it("matches the WebCrypto-computed X25519 pubkey from the clamped scalar", async () => {
    const seed = hexDecode("9d61b19deffd5a60ba844af492ec2cc44449c1f7039acab23db66cbbb654d973");
    const kp = await makeKeypair(seed);
    const converted = ed25519PubToX25519(kp.publicKey);

    const xPriv = await ed25519SeedToX25519PrivateKey(seed);
    const X25519_PKCS8_HEADER = new Uint8Array([
      0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
      0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
    ]);
    const pkcs8 = new Uint8Array(48);
    pkcs8.set(X25519_PKCS8_HEADER);
    pkcs8.set(xPriv, 16);
    const key = await globalThis.crypto.subtle.importKey(
      "pkcs8",
      pkcs8.buffer.slice(0),
      { name: "X25519" },
      true,
      ["deriveBits"],
    );
    const jwk = await globalThis.crypto.subtle.exportKey("jwk", key);
    // base64url-decode JWK x without depending on Node's Buffer
    const padded = jwk.x!.replace(/-/g, "+").replace(/_/g, "/");
    const binary = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
    const xPubFromWebCrypto = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) xPubFromWebCrypto[i] = binary.charCodeAt(i);

    expect(hexEncode(converted)).toBe(hexEncode(xPubFromWebCrypto));
  });
});
