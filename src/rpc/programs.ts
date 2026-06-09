import type { OctraClient } from "./client.js";
import { OctraRpcError } from "../core/errors.js";

export interface ProgramMetadata {
  address?: string;
  owner?: string;
  version?: string;
  code_hash?: string;
  balance?: string;
  [key: string]: unknown;
}

export interface ProgramAbi {
  methods?: unknown[];
  [key: string]: unknown;
}

export interface ProgramStorageResult {
  value?: unknown;
  [key: string]: unknown;
}

export interface ProgramListResult {
  programs?: ProgramMetadata[];
  [key: string]: unknown;
}

export interface ContractReceiptResult {
  success?: boolean;
  output?: unknown;
  error?: string;
  gas_used?: number;
  [key: string]: unknown;
}

export interface ContractCallResult {
  result?: unknown;
  [key: string]: unknown;
}

export interface ComputeAddressResult {
  address?: string;
  [key: string]: unknown;
}

export async function getProgram(
  client: OctraClient,
  address: string,
): Promise<ProgramMetadata> {
  return client.call<ProgramMetadata>("vm_contract", [address]);
}

export async function getAbi(
  client: OctraClient,
  address: string,
): Promise<ProgramAbi> {
  return client.call<ProgramAbi>("octra_contractAbi", [address]);
}

export async function getStorage(
  client: OctraClient,
  address: string,
  key: string,
): Promise<ProgramStorageResult> {
  return client.call<ProgramStorageResult>("octra_contractStorage", [address, key]);
}

export async function listPrograms(client: OctraClient): Promise<ProgramListResult> {
  return client.call<ProgramListResult>("octra_listContracts");
}

export async function getReceipt(
  client: OctraClient,
  txHash: string,
): Promise<ContractReceiptResult> {
  return client.call<ContractReceiptResult>("contract_receipt", [txHash]);
}

export async function callProgram(
  client: OctraClient,
  address: string,
  method: string,
  params?: unknown[],
  caller?: string,
): Promise<ContractCallResult> {
  const rpcParams: unknown[] = [address, method];
  if (params !== undefined) rpcParams.push(params);
  if (caller !== undefined) rpcParams.push(caller);
  return client.call<ContractCallResult>("contract_call", rpcParams);
}

export async function computeProgramAddress(
  client: OctraClient,
  bytecodeB64: string,
  deployer: string,
  nonce?: number,
): Promise<string> {
  const params: unknown[] = [bytecodeB64, deployer];
  if (nonce !== undefined) params.push(nonce);
  const result = await client.call<ComputeAddressResult>("octra_computeContractAddress", params);
  if (!result.address) throw new OctraRpcError(-1, "Node did not return a contract address");
  return result.address;
}
