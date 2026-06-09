import { pbkdf2Sha256 } from "../crypto/hash.js";
import { KEYSTORE_PBKDF2_ITERATIONS } from "../core/constants.js";

function subtle(): SubtleCrypto {
  return globalThis.crypto.subtle;
}

function ab(u8: Uint8Array): ArrayBuffer {
  return u8.buffer instanceof ArrayBuffer
    ? u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength)
    : new Uint8Array(u8).buffer;
}

export interface KeystoreData {
  priv: string;
  addr: string;
  rpc: string;
  explorer?: string;
  bridge_signer?: string;
  master_seed?: string;
  hd_index?: number;
  hd_version?: number;
  mnemonic?: string;
}

export async function encryptKeystore(plaintext: string, pin: string): Promise<Uint8Array> {
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const nonce = globalThis.crypto.getRandomValues(new Uint8Array(12));

  const keyBytes = await pbkdf2Sha256(
    new TextEncoder().encode(pin),
    salt,
    KEYSTORE_PBKDF2_ITERATIONS,
    256,
  );

  const aesKey = await subtle().importKey("raw", ab(keyBytes), "AES-GCM", false, ["encrypt"]);
  const ciphertextWithTag = new Uint8Array(
    await subtle().encrypt({ name: "AES-GCM", iv: ab(nonce), tagLength: 128 }, aesKey, new TextEncoder().encode(plaintext)),
  );

  // Format: salt(32) || nonce(12) || ciphertext(n) || tag(16)
  // Web Crypto appends the 16-byte tag to the ciphertext, so ciphertextWithTag is already (n+16) bytes
  const result = new Uint8Array(32 + 12 + ciphertextWithTag.length);
  result.set(salt, 0);
  result.set(nonce, 32);
  result.set(ciphertextWithTag, 44);
  return result;
}

export async function decryptKeystore(data: Uint8Array, pin: string): Promise<string> {
  if (data.length < 61) throw new Error("Keystore data too short");

  const salt = data.slice(0, 32);
  const nonce = data.slice(32, 44);
  const ciphertextWithTag = data.slice(44);

  const keyBytes = await pbkdf2Sha256(
    new TextEncoder().encode(pin),
    salt,
    KEYSTORE_PBKDF2_ITERATIONS,
    256,
  );

  const aesKey = await subtle().importKey("raw", ab(keyBytes), "AES-GCM", false, ["decrypt"]);

  let plaintext: ArrayBuffer;
  try {
    plaintext = await subtle().decrypt(
      { name: "AES-GCM", iv: ab(nonce), tagLength: 128 },
      aesKey,
      ab(ciphertextWithTag),
    );
  } catch {
    throw new Error("Decryption failed: wrong PIN or corrupted keystore");
  }

  return new TextDecoder().decode(plaintext);
}

export async function serializeKeystore(data: KeystoreData, pin: string): Promise<Uint8Array> {
  return encryptKeystore(JSON.stringify(data), pin);
}

export async function deserializeKeystore(raw: Uint8Array, pin: string): Promise<KeystoreData> {
  const json = await decryptKeystore(raw, pin);
  return JSON.parse(json) as KeystoreData;
}
