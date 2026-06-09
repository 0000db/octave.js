import type { OctraClient } from "./client.js";

export interface BalanceResult {
  formatted: string;
  raw: string;
  nonce: number;
  pending_nonce?: number;
  has_public_key?: boolean;
  [key: string]: unknown;
}

export interface AccountResult {
  address: string;
  balance?: BalanceResult;
  transactions?: unknown[];
  [key: string]: unknown;
}

export interface NonceResult {
  nonce: number;
  [key: string]: unknown;
}

export interface PublicKeyResult {
  public_key: string | null;
  [key: string]: unknown;
}

export interface ValidateAddressResult {
  valid: boolean;
  [key: string]: unknown;
}

export interface SupplyResult {
  total: string;
  max?: string;
  burned?: string;
  [key: string]: unknown;
}

export async function getBalance(client: OctraClient, address: string): Promise<BalanceResult> {
  return client.call<BalanceResult>("octra_balance", [address]);
}

export async function getAccount(
  client: OctraClient,
  address: string,
  limit?: number,
): Promise<AccountResult> {
  const params: unknown[] = [address];
  if (limit !== undefined) params.push(limit);
  return client.call<AccountResult>("octra_account", params);
}

export async function getNonce(client: OctraClient, address: string): Promise<number> {
  const result = await client.call<NonceResult>("octra_nonce", [address]);
  return result.nonce;
}

export async function getPublicKey(
  client: OctraClient,
  address: string,
): Promise<string | null> {
  const result = await client.call<PublicKeyResult>("octra_publicKey", [address]);
  return result.public_key;
}

export async function validateAddress(
  client: OctraClient,
  address: string,
): Promise<boolean> {
  const result = await client.call<ValidateAddressResult>("octra_validateAddress", [address]);
  return result.valid;
}

export async function getSupply(client: OctraClient): Promise<SupplyResult> {
  return client.call<SupplyResult>("octra_supply");
}
