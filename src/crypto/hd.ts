import { hmacSha512 } from "./hash.js";
import { HD_KEY } from "../core/constants.js";

const HD_KEY_BYTES = new TextEncoder().encode(HD_KEY);

export async function deriveHdSeed(
  masterSeed64: Uint8Array,
  index: number,
  hdVersion: 1 | 2 = 2,
): Promise<Uint8Array> {
  if (masterSeed64.length !== 64) throw new Error("Master seed must be 64 bytes");

  if (hdVersion === 2) {
    if (index === 0) {
      const mac = await hmacSha512(HD_KEY_BYTES, masterSeed64);
      return mac.slice(0, 32);
    }
    // v2 index>0: HMAC-SHA512("Octra seed", master_seed || 0x02 || index_le32)
    const data = new Uint8Array(69);
    data.set(masterSeed64, 0);
    data[64] = 2;
    new DataView(data.buffer).setUint32(65, index, true);
    const mac = await hmacSha512(HD_KEY_BYTES, data);
    return mac.slice(0, 32);
  }

  // v1: HMAC-SHA512("Octra seed", master_seed || index_le32)
  const data = new Uint8Array(68);
  data.set(masterSeed64, 0);
  new DataView(data.buffer).setUint32(64, index, true); // little-endian
  const mac = await hmacSha512(HD_KEY_BYTES, data);
  return mac.slice(0, 32);
}
