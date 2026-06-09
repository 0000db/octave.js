import type { OctraClient } from "./client.js";

export interface VerifySourceResult {
  verified?: boolean;
  [key: string]: unknown;
}

export interface SourceResult {
  source?: string;
  files?: Record<string, string>;
  [key: string]: unknown;
}

export async function verifySource(
  client: OctraClient,
  address: string,
  source: string,
  files?: Record<string, string>,
): Promise<VerifySourceResult> {
  const params: unknown[] = [address, source];
  if (files !== undefined) params.push(files);
  return client.call<VerifySourceResult>("contract_verify", params);
}

export async function saveAbi(
  client: OctraClient,
  address: string,
  abi: unknown,
): Promise<unknown> {
  return client.call("contract_saveAbi", [address, abi]);
}

export async function getSource(
  client: OctraClient,
  address: string,
): Promise<SourceResult> {
  return client.call<SourceResult>("contract_source", [address]);
}
