import type { OctraClient } from "./client.js";

export interface EpochResult {
  id?: number;
  validator?: string;
  timestamp?: number;
  state_root?: string;
  [key: string]: unknown;
}

export interface CurrentEpochResult {
  epoch_id?: number;
  root_count?: number;
  [key: string]: unknown;
}

export interface EpochListResult {
  epochs?: EpochResult[];
  total?: number;
  [key: string]: unknown;
}

export async function getCurrentEpoch(client: OctraClient): Promise<CurrentEpochResult> {
  return client.call<CurrentEpochResult>("epoch_current");
}

export async function getEpoch(client: OctraClient, epochId: number): Promise<EpochResult> {
  return client.call<EpochResult>("epoch_get", [epochId]);
}

export async function listEpochs(
  client: OctraClient,
  limit?: number,
  offset?: number,
): Promise<EpochListResult> {
  const params: unknown[] = [];
  if (limit !== undefined) params.push(limit);
  if (offset !== undefined) params.push(offset);
  return client.call<EpochListResult>("epoch_list", params);
}

export async function getEpochSummaries(
  client: OctraClient,
  epochIds: number[],
): Promise<EpochResult[]> {
  return client.call<EpochResult[]>("epoch_summaries", [epochIds]);
}
