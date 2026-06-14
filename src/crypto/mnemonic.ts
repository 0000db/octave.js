import { BIP39_WORDLIST } from "./bip39_wordlist.js";
import { sha256, pbkdf2Sha512 } from "./hash.js";
import { MNEMONIC_PBKDF2_ITERATIONS } from "../core/constants.js";

export type MnemonicStrength = 128 | 160 | 192 | 224 | 256;

export async function generateMnemonicAsync(strength: MnemonicStrength = 128): Promise<string> {
  if (![128, 160, 192, 224, 256].includes(strength)) {
    throw new Error(`Invalid mnemonic strength ${strength}; must be 128, 160, 192, 224, or 256`);
  }
  const entropyBytes = strength / 8;
  const checksumBits = strength / 32;
  const wordCount = (strength + checksumBits) / 11;
  const totalBits = wordCount * 11;
  const totalBytes = Math.ceil(totalBits / 8);

  const entropy = globalThis.crypto.getRandomValues(new Uint8Array(entropyBytes));
  const hash = await sha256(entropy);

  const bits = new Uint8Array(totalBytes);
  bits.set(entropy);
  // Pack the checksum bits into the byte(s) immediately after the entropy.
  // For 128-bit entropy: 4 checksum bits go into bits[16] high nibble (entropy ends on byte boundary, so this is just bits[16] = hash[0]).
  // For 256-bit entropy: 8 checksum bits = hash[0] → bits[32].
  // General formula: pack checksumBits bits starting at bit position entropyBits.
  for (let i = 0; i < checksumBits; i++) {
    const srcBit = (hash[Math.floor(i / 8)]! >> (7 - (i % 8))) & 1;
    const dstBitPos = strength + i;
    const dstByte = Math.floor(dstBitPos / 8);
    const dstOff = dstBitPos % 8;
    bits[dstByte] = (bits[dstByte]! | (srcBit << (7 - dstOff))) & 0xff;
  }

  const words: string[] = [];
  for (let i = 0; i < wordCount; i++) {
    const bitPos = i * 11;
    const byteIdx = Math.floor(bitPos / 8);
    const bitOff = bitPos % 8;

    const b0 = bits[byteIdx]!;
    const b1 = byteIdx + 1 < totalBytes ? bits[byteIdx + 1]! : 0;
    const b2 = byteIdx + 2 < totalBytes ? bits[byteIdx + 2]! : 0;
    let val = ((b0 << 16) | (b1 << 8) | b2) >>> 0;
    val = (val >>> (24 - 11 - bitOff)) & 0x7ff;

    words.push(BIP39_WORDLIST[val]!);
  }
  return words.join(" ");
}

// Backward-compat alias: 12-word default.
export async function generateMnemonic12Async(): Promise<string> {
  return generateMnemonicAsync(128);
}

export async function validateMnemonic(mnemonic: string): Promise<boolean> {
  const words = mnemonic
    .trim()
    .toLowerCase()
    .split(/\s+/)
    .filter((w) => w.length > 0);
  const validLengths = [12, 15, 18, 21, 24];
  if (!validLengths.includes(words.length)) return false;
  if (!words.every((w) => BIP39_WORDLIST.includes(w))) return false;

  // BIP39 checksum: totalBits = wordCount * 11 = entropyBits + checksumBits
  // checksumBits = entropyBits / 32, so totalBits / 33 = checksumBits
  const totalBits = words.length * 11;
  const checksumBits = totalBits / 33;
  const entropyBytes = (totalBits - checksumBits) / 8;

  // Unpack 11-bit word indices into a flat bit array
  const bits: number[] = [];
  for (const word of words) {
    const idx = BIP39_WORDLIST.indexOf(word);
    for (let i = 10; i >= 0; i--) bits.push((idx >> i) & 1);
  }

  // Reconstruct entropy bytes from the first entropyBits bits
  const entropy = new Uint8Array(entropyBytes);
  for (let i = 0; i < entropyBytes; i++) {
    let byte = 0;
    for (let j = 0; j < 8; j++) byte = (byte << 1) | bits[i * 8 + j]!;
    entropy[i] = byte;
  }

  // Compare the last checksumBits of the mnemonic against SHA256(entropy)
  const hash = await sha256(entropy);
  const entropyBits = entropyBytes * 8;
  for (let i = 0; i < checksumBits; i++) {
    const expected = (hash[Math.floor(i / 8)]! >> (7 - (i % 8))) & 1;
    if (bits[entropyBits + i] !== expected) return false;
  }

  return true;
}

export async function mnemonicToSeed(mnemonic: string, passphrase = ""): Promise<Uint8Array> {
  const enc = new TextEncoder();
  const password = enc.encode(mnemonic.trim().normalize("NFKD"));
  const salt = enc.encode(("mnemonic" + passphrase).normalize("NFKD"));
  return pbkdf2Sha512(password, salt, MNEMONIC_PBKDF2_ITERATIONS, 512);
}
