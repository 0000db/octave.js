import type { OpType } from "../core/types.js";

export interface UnsignedTransaction {
  from: string;
  to_: string;
  amount: string;
  nonce: number;
  ou: string;
  timestamp: number;
  op_type: OpType;
  encrypted_data?: string;
  message?: string;
}

export interface SignedTransaction extends UnsignedTransaction {
  signature: string;
  public_key: string;
}

function jsonEscape(s: string): string {
  let r = "";
  for (const ch of s) {
    const cp = ch.codePointAt(0)!;
    switch (ch) {
      case '"': r += '\\"'; break;
      case '\\': r += '\\\\'; break;
      case '\b': r += '\\b'; break;
      case '\f': r += '\\f'; break;
      case '\n': r += '\\n'; break;
      case '\r': r += '\\r'; break;
      case '\t': r += '\\t'; break;
      default:
        if (cp < 0x20) {
          r += `\\u${cp.toString(16).padStart(4, "0")}`;
        } else {
          r += ch;
        }
    }
  }
  return r;
}

export function canonicalJson(tx: UnsignedTransaction): string {
  let s =
    `{"from":"${jsonEscape(tx.from)}"` +
    `,"to_":"${jsonEscape(tx.to_)}"` +
    `,"amount":"${jsonEscape(tx.amount)}"` +
    `,"nonce":${tx.nonce}` +
    `,"ou":"${jsonEscape(tx.ou)}"` +
    `,"timestamp":${tx.timestamp}` +
    `,"op_type":"${jsonEscape(tx.op_type)}"`;
  if (tx.encrypted_data !== undefined) s += `,"encrypted_data":"${jsonEscape(tx.encrypted_data)}"`;
  if (tx.message !== undefined) s += `,"message":"${jsonEscape(tx.message)}"`;
  s += "}";
  return s;
}
