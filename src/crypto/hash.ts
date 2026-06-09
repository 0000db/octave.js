function subtle(): SubtleCrypto {
  return globalThis.crypto.subtle;
}

// Ensures the Uint8Array is backed by a plain ArrayBuffer (required by Web Crypto DOM types).
function ab(u8: Uint8Array): ArrayBuffer {
  return u8.buffer instanceof ArrayBuffer
    ? u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength)
    : new Uint8Array(u8).buffer;
}

export async function sha256(data: Uint8Array | string): Promise<Uint8Array> {
  const input = typeof data === "string" ? new TextEncoder().encode(data) : data;
  const buf = await subtle().digest("SHA-256", ab(input));
  return new Uint8Array(buf);
}

export async function hmacSha512(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const cryptoKey = await subtle().importKey(
    "raw",
    ab(key),
    { name: "HMAC", hash: "SHA-512" },
    false,
    ["sign"],
  );
  const mac = await subtle().sign("HMAC", cryptoKey, ab(data));
  return new Uint8Array(mac);
}

export async function pbkdf2Sha256(
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  bits: number,
): Promise<Uint8Array> {
  const base = await subtle().importKey("raw", ab(password), "PBKDF2", false, ["deriveBits"]);
  const derived = await subtle().deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: ab(salt), iterations },
    base,
    bits,
  );
  return new Uint8Array(derived);
}

export async function pbkdf2Sha512(
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  bits: number,
): Promise<Uint8Array> {
  const base = await subtle().importKey("raw", ab(password), "PBKDF2", false, ["deriveBits"]);
  const derived = await subtle().deriveBits(
    { name: "PBKDF2", hash: "SHA-512", salt: ab(salt), iterations },
    base,
    bits,
  );
  return new Uint8Array(derived);
}
