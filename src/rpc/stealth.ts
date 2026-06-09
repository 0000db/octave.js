import type { OctraClient } from "./client.js";

export interface ViewPubkeyResult {
  view_pubkey?: string;
  [key: string]: unknown;
}

export interface StealthOutput {
  hash?: string;
  amount?: string;
  ephemeral_pubkey?: string;
  encrypted_data?: string;
  epoch?: number;
  [key: string]: unknown;
}

export interface StealthOutputsResult {
  outputs?: StealthOutput[];
  [key: string]: unknown;
}

export async function getViewPubkey(
  client: OctraClient,
  address: string,
): Promise<ViewPubkeyResult> {
  return client.call<ViewPubkeyResult>("octra_viewPubkey", [address]);
}

export async function getStealthOutputs(
  client: OctraClient,
  fromEpoch?: number,
): Promise<StealthOutputsResult> {
  const params: unknown[] = [];
  if (fromEpoch !== undefined) params.push(fromEpoch);
  return client.call<StealthOutputsResult>("octra_stealthOutputs", params);
}
