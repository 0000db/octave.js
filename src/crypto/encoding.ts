const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function base58Encode(data: Uint8Array): string {
  let leadingZeroes = 0;
  for (const b of data) {
    if (b !== 0) break;
    leadingZeroes++;
  }

  let n = 0n;
  for (const b of data) {
    n = n * 256n + BigInt(b);
  }

  let result = "";
  while (n > 0n) {
    const rem = Number(n % 58n);
    n /= 58n;
    result = (BASE58_ALPHABET[rem] ?? "") + result;
  }

  return "1".repeat(leadingZeroes) + result;
}

export function base58Decode(s: string): Uint8Array {
  let n = 0n;
  for (const ch of s) {
    const idx = BASE58_ALPHABET.indexOf(ch);
    if (idx < 0) throw new Error(`Invalid base58 character: ${ch}`);
    n = n * 58n + BigInt(idx);
  }

  const bytes: number[] = [];
  while (n > 0n) {
    bytes.unshift(Number(n & 0xffn));
    n >>= 8n;
  }

  let leadingOnes = 0;
  for (const ch of s) {
    if (ch !== "1") break;
    leadingOnes++;
  }

  const result = new Uint8Array(leadingOnes + bytes.length);
  result.set(bytes, leadingOnes);
  return result;
}

export function base64Encode(data: Uint8Array): string {
  let binary = "";
  const chunkSize = 8192;
  for (let i = 0; i < data.length; i += chunkSize) {
    binary += String.fromCharCode(...data.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

export function base64Decode(s: string): Uint8Array {
  const binary = atob(s);
  const result = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    result[i] = binary.charCodeAt(i);
  }
  return result;
}

export function base64UrlEncode(data: Uint8Array): string {
  return base64Encode(data).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64UrlDecode(s: string): Uint8Array {
  const padded = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = (4 - (padded.length % 4)) % 4;
  return base64Decode(padded + "=".repeat(pad));
}

export function hexEncode(data: Uint8Array): string {
  return Array.from(data)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function hexDecode(s: string): Uint8Array {
  if (s.length % 2 !== 0) throw new Error("Hex string has odd length");
  const result = new Uint8Array(s.length / 2);
  for (let i = 0; i < result.length; i++) {
    result[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  }
  return result;
}
