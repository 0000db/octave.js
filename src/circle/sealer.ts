import { sha256, pbkdf2Sha256 } from "../crypto/hash.js";
import { hexEncode } from "../crypto/encoding.js";
import { KEYSTORE_PBKDF2_ITERATIONS } from "../core/constants.js";

const OCRS1_MAGIC = new TextEncoder().encode("OCRS1");
// Shares the keystore's PBKDF2 iteration count so both passphrase-derived KEKs track the
// same OWASP 2024 PBKDF2-SHA256 guidance and cannot drift apart.
// BREAKING: assets sealed with previous (100_000) iterations cannot be unsealed by this version.
const SEAL_PBKDF2_ITERATIONS = KEYSTORE_PBKDF2_ITERATIONS;

export type PaddingClass = "4k" | "16k" | "32k" | "128k";

const PADDING_SIZES: Record<PaddingClass, number> = {
  "4k": 4096,
  "16k": 16384,
  "32k": 32768,
  "128k": 131072,
};

function subtle(): SubtleCrypto {
  return globalThis.crypto.subtle;
}

function ab(u8: Uint8Array): ArrayBuffer {
  return u8.buffer instanceof ArrayBuffer
    ? u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength)
    : new Uint8Array(u8).buffer;
}

export async function deriveReadKey(circleId: string, keyId: string, passphrase: string): Promise<Uint8Array> {
  const enc = new TextEncoder();
  const password = enc.encode(passphrase);
  const salt = enc.encode(`${circleId}:${keyId}`);
  return pbkdf2Sha256(password, salt, SEAL_PBKDF2_ITERATIONS, 256);
}

export async function computeResourceKey(circleId: string, canonicalPath: string): Promise<string> {
  const path = canonicalPath.startsWith("/") ? canonicalPath : `/${canonicalPath}`;
  const enc = new TextEncoder();
  const data = enc.encode(`octra:circle_resource_key:v1${circleId}${path}`);
  const hash = await sha256(data);
  return hexEncode(hash);
}

export async function sealAsset(
  plaintext: Uint8Array,
  readKey: Uint8Array,
  paddingClass?: PaddingClass,
): Promise<{ ciphertext: Uint8Array; plaintextHash: string }> {
  const plaintextHash = hexEncode(await sha256(plaintext));

  const nonce = globalThis.crypto.getRandomValues(new Uint8Array(12));

  // Length-prefix the plaintext (4-byte LE), then optionally pad.
  const lenPrefix = new Uint8Array(4);
  new DataView(lenPrefix.buffer).setUint32(0, plaintext.length, true);
  let frame = new Uint8Array(4 + plaintext.length);
  frame.set(lenPrefix);
  frame.set(plaintext, 4);

  if (paddingClass) {
    const target = PADDING_SIZES[paddingClass];
    if (frame.length < target) {
      const padded = new Uint8Array(target);
      padded.set(frame);
      frame = padded;
    }
  }

  const aesKey = await subtle().importKey("raw", ab(readKey), "AES-GCM", false, ["encrypt"]);
  const encrypted = new Uint8Array(
    await subtle().encrypt({ name: "AES-GCM", iv: ab(nonce), tagLength: 128 }, aesKey, ab(frame)),
  );

  // Format: OCRS1(5) || nonce(12) || AES-GCM(frame)(n+16)
  const out = new Uint8Array(5 + 12 + encrypted.length);
  out.set(OCRS1_MAGIC, 0);
  out.set(nonce, 5);
  out.set(encrypted, 17);

  return { ciphertext: out, plaintextHash };
}

export async function unsealAsset(
  ciphertext: Uint8Array,
  readKey: Uint8Array,
  expectedPlaintextHash?: string,
): Promise<Uint8Array> {
  if (ciphertext.length < 17 + 16) throw new Error("Ciphertext too short for OCRS1 envelope");

  const magic = ciphertext.slice(0, 5);
  if (new TextDecoder().decode(magic) !== "OCRS1") throw new Error("Invalid OCRS1 magic");

  const nonce = ciphertext.slice(5, 17);
  const encrypted = ciphertext.slice(17);

  const aesKey = await subtle().importKey("raw", ab(readKey), "AES-GCM", false, ["decrypt"]);

  let frame: ArrayBuffer;
  try {
    frame = await subtle().decrypt({ name: "AES-GCM", iv: ab(nonce), tagLength: 128 }, aesKey, ab(encrypted));
  } catch {
    throw new Error("Decryption failed: wrong key or corrupted ciphertext");
  }

  const frameView = new DataView(frame);
  const originalLen = frameView.getUint32(0, true);
  const plaintext = new Uint8Array(frame, 4, originalLen);

  if (expectedPlaintextHash !== undefined) {
    const actualHash = hexEncode(await sha256(plaintext));
    if (actualHash !== expectedPlaintextHash) {
      throw new Error(`Plaintext hash mismatch: expected ${expectedPlaintextHash}, got ${actualHash}`);
    }
  }

  return plaintext;
}
