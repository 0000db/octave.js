import { base58Encode, base64UrlDecode } from "./encoding.js";
import { sha256 } from "./hash.js";
import type { Keypair, Address } from "../core/types.js";
import { ADDRESS_PREFIX, ADDRESS_B58_LENGTH, ADDRESS_TOTAL_LENGTH } from "../core/constants.js";
import { OctraValidationError } from "../core/errors.js";

const BASE58_ALPHABET_SET = new Set("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz");

// Local format check: prefix, total length, and base58 alphabet. Does NOT validate that the
// address corresponds to an account that exists on chain. There is no on-address checksum
// in the Octra spec, so a single-character typo within the base58 alphabet is undetectable here.
export function validateAddressFormat(addr: string): boolean {
  if (typeof addr !== "string") return false;
  if (addr.length !== ADDRESS_TOTAL_LENGTH) return false;
  if (!addr.startsWith(ADDRESS_PREFIX)) return false;
  for (let i = ADDRESS_PREFIX.length; i < addr.length; i++) {
    if (!BASE58_ALPHABET_SET.has(addr[i]!)) return false;
  }
  return true;
}

export function assertAddressFormat(addr: string): asserts addr is Address {
  if (!validateAddressFormat(addr)) {
    throw new OctraValidationError("address", `Malformed Octra address: "${addr}"`);
  }
}

const ED25519_PKCS8_HEADER = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
  0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

const X25519_PKCS8_HEADER = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
  0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
]);

function subtle(): SubtleCrypto {
  return globalThis.crypto.subtle;
}

function ab(u8: Uint8Array): ArrayBuffer {
  return u8.buffer instanceof ArrayBuffer
    ? u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength)
    : new Uint8Array(u8).buffer;
}

async function importEd25519Seed(seed32: Uint8Array): Promise<CryptoKey> {
  if (seed32.length !== 32) {
    throw new OctraValidationError("seed32", `Seed must be exactly 32 bytes, got ${seed32.length}`);
  }
  const pkcs8 = new Uint8Array(48);
  pkcs8.set(ED25519_PKCS8_HEADER);
  pkcs8.set(seed32, 16);
  return subtle().importKey("pkcs8", ab(pkcs8), { name: "Ed25519" }, true, ["sign"]);
}

export async function keypairFromSeed(seed32: Uint8Array): Promise<{ signingKey: CryptoKey; publicKey: Uint8Array }> {
  const signingKey = await importEd25519Seed(seed32);
  const jwk = await subtle().exportKey("jwk", signingKey);
  const publicKey = base64UrlDecode(jwk.x!);
  return { signingKey, publicKey };
}

export async function deriveAddress(publicKey: Uint8Array): Promise<Address> {
  const hash = await sha256(publicKey);
  let b58 = base58Encode(hash);
  while (b58.length < ADDRESS_B58_LENGTH) b58 = "1" + b58;
  return (ADDRESS_PREFIX + b58) as Address;
}

export async function makeKeypair(seed32: Uint8Array): Promise<Keypair & { signingKey: CryptoKey }> {
  const { signingKey, publicKey } = await keypairFromSeed(seed32);
  const hash = await sha256(publicKey);
  let b58 = base58Encode(hash);
  while (b58.length < ADDRESS_B58_LENGTH) b58 = "1" + b58;
  const address = (ADDRESS_PREFIX + b58) as Address;
  return { secretKey: seed32, publicKey, address, signingKey };
}

export async function generateKeypair(): Promise<Keypair & { signingKey: CryptoKey }> {
  const seed = globalThis.crypto.getRandomValues(new Uint8Array(32));
  return makeKeypair(seed);
}

export async function signBytes(message: Uint8Array, signingKey: CryptoKey): Promise<Uint8Array> {
  const sig = await subtle().sign({ name: "Ed25519" }, signingKey, ab(message));
  return new Uint8Array(sig);
}

export async function verifySignature(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array,
): Promise<boolean> {
  const pubKey = await subtle().importKey("raw", ab(publicKey), { name: "Ed25519" }, false, ["verify"]);
  return subtle().verify({ name: "Ed25519" }, pubKey, ab(signature), ab(message));
}

export async function getSigningKey(seed32: Uint8Array): Promise<CryptoKey> {
  return importEd25519Seed(seed32);
}

export async function ed25519SeedToX25519PrivateKey(edSeed32: Uint8Array): Promise<Uint8Array> {
  const hashBuf = await subtle().digest("SHA-512", ab(edSeed32));
  const h = new Uint8Array(hashBuf).slice(0, 32);
  h[0]! &= 248;
  h[31]! &= 127;
  h[31]! |= 64;
  return h;
}

export function ed25519PubToX25519(edPub: Uint8Array): Uint8Array {
  const P = (1n << 255n) - 19n;

  function modpow(base: bigint, exp: bigint, mod: bigint): bigint {
    let result = 1n;
    base %= mod;
    while (exp > 0n) {
      if (exp & 1n) result = (result * base) % mod;
      exp >>= 1n;
      base = (base * base) % mod;
    }
    return result;
  }

  const bytes = edPub.slice();
  bytes[31]! &= 0x7f;

  let y = 0n;
  for (let i = 31; i >= 0; i--) {
    y = (y << 8n) | BigInt(bytes[i]!);
  }

  if (y === 1n) {
    throw new Error("Ed25519 identity point cannot be converted to X25519");
  }
  const u = ((1n + y) * modpow(1n - y + P, P - 2n, P)) % P;
  if (u === 0n) {
    throw new Error("Ed25519 public key maps to the X25519 low-order point");
  }

  const out = new Uint8Array(32);
  let tmp = u;
  for (let i = 0; i < 32; i++) {
    out[i] = Number(tmp & 0xffn);
    tmp >>= 8n;
  }
  return out;
}

export async function x25519DeriveShared(
  myX25519PrivateKey: Uint8Array,
  theirX25519PublicKey: Uint8Array,
): Promise<Uint8Array> {
  const pkcs8 = new Uint8Array(48);
  pkcs8.set(X25519_PKCS8_HEADER);
  pkcs8.set(myX25519PrivateKey, 16);

  const privKey = await subtle().importKey("pkcs8", ab(pkcs8), { name: "X25519" }, false, ["deriveBits"]);
  const pubKey = await subtle().importKey("raw", ab(theirX25519PublicKey), { name: "X25519" }, false, []);

  const shared = await subtle().deriveBits({ name: "X25519", public: pubKey }, privKey, 256);
  return new Uint8Array(shared);
}
