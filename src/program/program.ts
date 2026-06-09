import type { OctraClient } from "../rpc/client.js";
import type { Signer } from "../core/types.js";
import { getNonce } from "../rpc/accounts.js";
import { submit } from "../rpc/transactions.js";
import {
  getProgram, getAbi, getStorage, getReceipt, callProgram, computeProgramAddress,
} from "../rpc/programs.js";
import { compileAml, compileAmlMulti } from "../rpc/compilation.js";
import { buildContractCall, buildDeploy, signTx } from "../tx/builder.js";
import type {
  ProgramMetadata, ProgramAbi, ProgramStorageResult, ContractReceiptResult, ContractCallResult, CompileResult,
} from "../rpc/index.js";

export interface SendCallOptions {
  amount?: bigint;
  fee: string;
}

export interface DeployOptions {
  fee: string;
}

export class Program {
  readonly address: string;
  readonly abi: unknown;
  readonly client: OctraClient;
  readonly signer: Signer;

  constructor(address: string, abi: unknown, client: OctraClient, signer: Signer) {
    this.address = address;
    this.abi = abi;
    this.client = client;
    this.signer = signer;
  }

  async metadata(): Promise<ProgramMetadata> {
    return getProgram(this.client, this.address);
  }

  async fetchAbi(): Promise<ProgramAbi> {
    return getAbi(this.client, this.address);
  }

  async getStorage(key: string): Promise<ProgramStorageResult> {
    return getStorage(this.client, this.address, key);
  }

  async call(method: string, params: unknown[] = [], caller?: string): Promise<ContractCallResult> {
    return callProgram(this.client, this.address, method, params, caller ?? this.signer.address as string);
  }

  async send(method: string, params: unknown[] = [], opts: SendCallOptions = { fee: "5000" }): Promise<string> {
    const nonce = await getNonce(this.client, this.signer.address as string);
    const tx = buildContractCall({
      from: this.signer.address as string,
      contract: this.address,
      method,
      params,
      amount: opts.amount,
      nonce: nonce + 1,
      fee: opts.fee,
    });
    const signed = await signTx(tx, this.signer);
    return submit(this.client, signed);
  }

  async getReceipt(txHash: string): Promise<ContractReceiptResult> {
    return getReceipt(this.client, txHash);
  }
}

export async function compileProgram(client: OctraClient, source: string): Promise<CompileResult> {
  return compileAml(client, source);
}

export async function compileProgramMulti(
  client: OctraClient,
  files: Record<string, string>,
  main: string,
): Promise<CompileResult> {
  return compileAmlMulti(client, files, main);
}

export async function deployProgram(
  client: OctraClient,
  signer: Signer,
  bytecodeB64: string,
  opts: DeployOptions,
): Promise<{ address: string; txHash: string }> {
  const nonce = await getNonce(client, signer.address as string);
  const predictedAddress = await computeProgramAddress(client, bytecodeB64, signer.address as string, nonce + 1);
  const tx = buildDeploy({
    from: signer.address as string,
    bytecodeB64,
    nonce: nonce + 1,
    fee: opts.fee,
  });
  const signed = await signTx(tx, signer);
  const hash = await submit(client, signed);
  return { address: predictedAddress, txHash: hash };
}
