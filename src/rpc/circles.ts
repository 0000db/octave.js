import type { OctraClient } from "./client.js";

export interface CircleInfo {
  circle_id?: string;
  owner?: string;
  privacy_class?: string;
  runtime?: string;
  [key: string]: unknown;
}

export interface CircleAssetResult {
  content?: string;
  content_type?: string;
  [key: string]: unknown;
}

export interface CircleCiphertextResult {
  ciphertext_b64?: string;
  resource_key?: string;
  plaintext_hash?: string;
  key_id?: string;
  [key: string]: unknown;
}

export async function getCircleInfo(
  client: OctraClient,
  circleId: string,
): Promise<CircleInfo> {
  return client.call<CircleInfo>("circle_info", [circleId]);
}

export async function getCircleAsset(
  client: OctraClient,
  circleId: string,
  path: string,
): Promise<CircleAssetResult> {
  return client.call<CircleAssetResult>("circle_asset", [circleId, path]);
}

export async function getCircleAssetCiphertext(
  client: OctraClient,
  circleId: string,
  path: string,
): Promise<CircleCiphertextResult> {
  return client.call<CircleCiphertextResult>("circle_asset_ciphertext", [circleId, path]);
}

export async function getCircleAssetCiphertextByKey(
  client: OctraClient,
  circleId: string,
  resourceKey: string,
): Promise<CircleCiphertextResult> {
  return client.call<CircleCiphertextResult>("circle_asset_ciphertext_by_resource_key", [
    circleId,
    resourceKey,
  ]);
}
