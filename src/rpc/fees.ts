import type { OctraClient } from "./client.js";

export interface RecommendedFeeResult {
  minimum?: string;
  base?: string;
  recommended?: string;
  fast?: string;
  [key: string]: unknown;
}

export interface StagingViewResult {
  transactions?: unknown[];
  [key: string]: unknown;
}

export interface StagingStatsResult {
  count?: number;
  [key: string]: unknown;
}

export interface EstimateOuResult {
  percentiles?: Record<string, string>;
  [key: string]: unknown;
}

export async function getRecommendedFee(
  client: OctraClient,
  opType?: string,
): Promise<RecommendedFeeResult> {
  const params: unknown[] = [];
  if (opType !== undefined) params.push(opType);
  return client.call<RecommendedFeeResult>("octra_recommendedFee", params);
}

export async function getStagingView(client: OctraClient): Promise<StagingViewResult> {
  return client.call<StagingViewResult>("staging_view");
}

export async function getStagingStats(client: OctraClient): Promise<StagingStatsResult> {
  return client.call<StagingStatsResult>("staging_stats");
}

export async function estimateOu(client: OctraClient): Promise<EstimateOuResult> {
  return client.call<EstimateOuResult>("staging_estimateOu");
}

export async function removeStagingTx(client: OctraClient, txHash: string): Promise<unknown> {
  return client.call("staging_remove", [txHash]);
}
