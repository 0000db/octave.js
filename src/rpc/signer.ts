import type { OctraClient } from "./client.js";
import type { Signer } from "../core/types.js";
import { OctraRpcError } from "../core/errors.js";
import { getBalance } from "./accounts.js";
import { submit } from "./transactions.js";
import { buildTransfer, signTx, txHash } from "../tx/builder.js";

export interface SendTransferParams {
  to: string;
  amount: bigint;
  fee: string;
  message?: string;
}

export async function signAndSend(
  client: OctraClient,
  signer: Signer,
  params: SendTransferParams,
): Promise<string> {
  const balance = await getBalance(client, signer.address as string);
  const rawNonce = balance.pending_nonce ?? balance.nonce;
  if (rawNonce == null || !Number.isFinite(rawNonce)) {
    throw new OctraRpcError(-1, `Cannot determine nonce for ${signer.address as string}`);
  }
  const nonce = rawNonce + 1;
  const tx = buildTransfer({
    from: signer.address as string,
    to: params.to,
    amount: params.amount,
    nonce,
    fee: params.fee,
    message: params.message,
  });
  const signed = await signTx(tx, signer);
  return submit(client, signed);
}
