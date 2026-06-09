import type { OctraClient } from "./client.js";

export interface RegisterPublicKeyResult {
  [key: string]: unknown;
}

export interface PvacPubkeyResult {
  pvac_pubkey?: string;
  [key: string]: unknown;
}

export interface EncryptedCipherResult {
  cipher?: string;
  [key: string]: unknown;
}

export interface EncryptedBalanceResult {
  balance?: unknown;
  [key: string]: unknown;
}

export async function registerPublicKey(
  client: OctraClient,
  address: string,
  publicKeyB64: string,
  signatureB64: string,
): Promise<RegisterPublicKeyResult> {
  return client.call<RegisterPublicKeyResult>("octra_registerPublicKey", [
    address,
    publicKeyB64,
    signatureB64,
  ]);
}

export async function registerPvacPubkey(
  client: OctraClient,
  address: string,
  pvacPubkeyB64: string,
  signatureB64: string,
  publicKeyB64: string,
  aesKatHex?: string,
): Promise<unknown> {
  return client.call("octra_registerPvacPubkey", [
    address,
    pvacPubkeyB64,
    signatureB64,
    publicKeyB64,
    aesKatHex ?? "",
  ]);
}

export async function getPvacPubkey(
  client: OctraClient,
  address: string,
): Promise<PvacPubkeyResult> {
  return client.call<PvacPubkeyResult>("octra_pvacPubkey", [address]);
}

export async function getEncryptedCipher(
  client: OctraClient,
  address: string,
): Promise<EncryptedCipherResult> {
  return client.call<EncryptedCipherResult>("octra_encryptedCipher", [address]);
}

export async function getEncryptedBalance(
  client: OctraClient,
  address: string,
  signatureB64: string,
  publicKeyB64: string,
): Promise<EncryptedBalanceResult> {
  return client.call<EncryptedBalanceResult>("octra_encryptedBalance", [
    address,
    signatureB64,
    publicKeyB64,
  ]);
}
