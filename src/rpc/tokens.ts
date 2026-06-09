import type { OctraClient } from "./client.js";

export interface TokenBalance {
  address?: string;
  symbol?: string;
  name?: string;
  balance?: string;
  decimals?: number;
  [key: string]: unknown;
}

export interface TokenTransfer {
  hash?: string;
  from?: string;
  to?: string;
  amount?: string;
  token?: string;
  timestamp?: number;
  [key: string]: unknown;
}

export interface TokenTransfersResult {
  transfers?: TokenTransfer[];
  total?: number;
  [key: string]: unknown;
}

export async function getTokensByAddress(
  client: OctraClient,
  address: string,
): Promise<TokenBalance[]> {
  return client.call<TokenBalance[]>("octra_tokensByAddress", [address]);
}

export async function getTokenTransfersByAddress(
  client: OctraClient,
  address: string,
  limit?: number,
  offset?: number,
): Promise<TokenTransfersResult> {
  const params: unknown[] = [address];
  if (limit !== undefined) params.push(limit);
  if (offset !== undefined) params.push(offset);
  return client.call<TokenTransfersResult>("octra_tokenTransfersByAddress", params);
}
