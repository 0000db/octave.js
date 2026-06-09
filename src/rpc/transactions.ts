import type { OctraClient } from "./client.js";
import type { SignedTransaction } from "../tx/canonical.js";
import { OctraSubmitError } from "../core/errors.js";

export type TxStatus = "pending" | "confirmed" | "rejected" | "dropped";

export interface SubmitResult {
  tx_hash?: string;
  status?: string;
  [key: string]: unknown;
}

export interface TransactionResult {
  hash?: string;
  status?: TxStatus;
  from?: string;
  to_?: string;
  amount?: string;
  nonce?: number;
  timestamp?: number;
  op_type?: string;
  signature?: string;
  public_key?: string;
  error?: { reason?: string };
  [key: string]: unknown;
}

export interface TransactionListResult {
  transactions?: TransactionResult[];
  total?: number;
  [key: string]: unknown;
}

export interface TotalTransactionsResult {
  confirmed?: number;
  staging?: number;
  total?: number;
  [key: string]: unknown;
}

export interface SearchResult {
  type?: string;
  data?: unknown;
  [key: string]: unknown;
}

export async function submit(
  client: OctraClient,
  tx: SignedTransaction,
): Promise<string> {
  const result = await client.call<SubmitResult>("octra_submit", [tx]);
  if (!result.tx_hash) {
    throw new OctraSubmitError(JSON.stringify(result));
  }
  return result.tx_hash;
}

export async function submitBatch(
  client: OctraClient,
  txs: SignedTransaction[],
): Promise<SubmitResult[]> {
  const results = await client.call<SubmitResult[]>("octra_submitBatch", [txs]);
  const failed = results
    .map((r, i) => ({ r, i }))
    .filter(({ r }) => !r.tx_hash);
  if (failed.length > 0) {
    const details = failed.map(({ r, i }) => `[${i}]: ${JSON.stringify(r)}`).join(", ");
    throw new OctraSubmitError(`${failed.length} of ${results.length} transactions failed: ${details}`);
  }
  return results;
}

export async function getTransaction(
  client: OctraClient,
  hash: string,
): Promise<TransactionResult> {
  return client.call<TransactionResult>("octra_transaction", [hash]);
}

export async function getRecentTransactions(
  client: OctraClient,
  limit?: number,
  offset?: number,
): Promise<TransactionListResult> {
  const params: unknown[] = [];
  if (limit !== undefined) params.push(limit);
  if (offset !== undefined) params.push(offset);
  return client.call<TransactionListResult>("octra_recentTransactions", params);
}

export async function getTransactions(
  client: OctraClient,
  epochId?: number,
  limit?: number,
): Promise<TransactionListResult> {
  const params: unknown[] = [];
  if (epochId !== undefined) params.push(epochId);
  if (limit !== undefined) params.push(limit);
  return client.call<TransactionListResult>("octra_transactions", params);
}

export async function getTransactionsByAddress(
  client: OctraClient,
  address: string,
  limit?: number,
  offset?: number,
): Promise<TransactionListResult> {
  const params: unknown[] = [address];
  if (limit !== undefined) params.push(limit);
  if (offset !== undefined) params.push(offset);
  return client.call<TransactionListResult>("octra_transactionsByAddress", params);
}

export async function getTransactionsByEpoch(
  client: OctraClient,
  epochId: number,
  limit?: number,
  offset?: number,
): Promise<TransactionListResult> {
  const params: unknown[] = [epochId];
  if (limit !== undefined) params.push(limit);
  if (offset !== undefined) params.push(offset);
  return client.call<TransactionListResult>("octra_transactionsByEpoch", params);
}

export async function getTotalTransactions(
  client: OctraClient,
): Promise<TotalTransactionsResult> {
  return client.call<TotalTransactionsResult>("octra_totalTransactions");
}

export async function search(
  client: OctraClient,
  query: string,
): Promise<SearchResult> {
  return client.call<SearchResult>("octra_search", [query]);
}
