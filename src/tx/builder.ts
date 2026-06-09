import { sha256 } from "../crypto/hash.js";
import { hexEncode, base64Encode } from "../crypto/encoding.js";
import { signBytes } from "../crypto/keypair.js";
import type { Signer, OpType } from "../core/types.js";
import { canonicalJson } from "./canonical.js";
import type { UnsignedTransaction, SignedTransaction } from "./canonical.js";

export interface TransferParams {
  from: string;
  to: string;
  amount: bigint;
  nonce: number;
  fee: string;
  timestamp?: number;
  message?: string;
}

export interface ContractCallParams {
  from: string;
  contract: string;
  method: string;
  params: unknown[];
  amount?: bigint;
  nonce: number;
  fee: string;
  timestamp?: number;
}

export interface RegisterPublicKeyParams {
  from: string;
  nonce: number;
  fee: string;
  timestamp?: number;
}

export interface DeployParams {
  from: string;
  bytecodeB64: string;
  nonce: number;
  fee: string;
  timestamp?: number;
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

export function buildTransfer(params: TransferParams): UnsignedTransaction {
  return {
    from: params.from,
    to_: params.to,
    amount: params.amount.toString(),
    nonce: params.nonce,
    ou: params.fee,
    timestamp: params.timestamp ?? nowSeconds(),
    op_type: "standard",
    ...(params.message ? { message: params.message } : {}),
  };
}

export function buildContractCall(params: ContractCallParams): UnsignedTransaction {
  return {
    from: params.from,
    to_: params.contract,
    amount: (params.amount ?? 0n).toString(),
    nonce: params.nonce,
    ou: params.fee,
    timestamp: params.timestamp ?? nowSeconds(),
    op_type: "contract_call",
    message: JSON.stringify({ method: params.method, params: params.params }),
  };
}

export function buildDeploy(params: DeployParams): UnsignedTransaction {
  return {
    from: params.from,
    to_: params.from,
    amount: "0",
    nonce: params.nonce,
    ou: params.fee,
    timestamp: params.timestamp ?? nowSeconds(),
    op_type: "deploy",
    message: params.bytecodeB64,
  };
}

export function buildRegisterPublicKey(params: RegisterPublicKeyParams): UnsignedTransaction {
  return {
    from: params.from,
    to_: params.from,
    amount: "0",
    nonce: params.nonce,
    ou: params.fee,
    timestamp: params.timestamp ?? nowSeconds(),
    op_type: "register_pubkey",
  };
}

export function buildRaw(fields: {
  from: string;
  to_: string;
  amount: string;
  nonce: number;
  ou: string;
  op_type: OpType;
  timestamp?: number;
  encrypted_data?: string;
  message?: string;
}): UnsignedTransaction {
  return {
    ...fields,
    timestamp: fields.timestamp ?? nowSeconds(),
  };
}

export async function signTx(tx: UnsignedTransaction, signer: Signer): Promise<SignedTransaction> {
  const canonical = canonicalJson(tx);
  const msgBytes = new TextEncoder().encode(canonical);
  const sigBytes = await signer.sign(msgBytes);
  return {
    ...tx,
    signature: base64Encode(sigBytes),
    public_key: base64Encode(signer.publicKeyBytes),
  };
}

export async function signTxWithKey(
  tx: UnsignedTransaction,
  signingKey: CryptoKey,
  publicKey: Uint8Array,
): Promise<SignedTransaction> {
  const canonical = canonicalJson(tx);
  const msgBytes = new TextEncoder().encode(canonical);
  const sigBytes = await signBytes(msgBytes, signingKey);
  return {
    ...tx,
    signature: base64Encode(sigBytes),
    public_key: base64Encode(publicKey),
  };
}

export async function txHash(tx: UnsignedTransaction): Promise<string> {
  const canonical = canonicalJson(tx);
  const hash = await sha256(new TextEncoder().encode(canonical));
  return hexEncode(hash);
}
