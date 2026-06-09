import type { OctraClient } from "../rpc/client.js";
import type { Signer } from "../core/types.js";
import { OctraRpcError } from "../core/errors.js";
import { getNonce } from "../rpc/accounts.js";
import { submit } from "../rpc/transactions.js";
import { callProgram } from "../rpc/programs.js";
import { buildContractCall, signTx } from "../tx/builder.js";
export { parseToken, formatToken } from "../units/oct.js";

export interface TokenMetadata {
  name: string;
  symbol: string;
  totalSupply: bigint;
  decimals: number;
}

export interface TransferOptions {
  fee: string;
}

function safeBigInt(value: unknown, field: string): bigint {
  const s = String(value ?? "0");
  try {
    return BigInt(s);
  } catch {
    throw new OctraRpcError(-1, `Unexpected ${field} value from contract: ${s}`);
  }
}

export class Ocs01Token {
  readonly address: string;
  readonly client: OctraClient;
  readonly signer: Signer;

  constructor(address: string, client: OctraClient, signer: Signer) {
    this.address = address;
    this.client = client;
    this.signer = signer;
  }

  async metadata(): Promise<TokenMetadata> {
    const [nameRes, symbolRes, supplyRes] = await Promise.all([
      callProgram(this.client, this.address, "get_name", []),
      callProgram(this.client, this.address, "get_symbol", []),
      callProgram(this.client, this.address, "get_total_supply", []),
    ]);

    const decimalsRes = await callProgram(this.client, this.address, "get_decimals", []).catch(() => ({ result: 6 }));

    return {
      name: String(nameRes.result ?? ""),
      symbol: String(symbolRes.result ?? ""),
      totalSupply: safeBigInt(supplyRes.result, "total_supply"),
      decimals: Number(decimalsRes.result ?? 6),
    };
  }

  async balanceOf(address: string): Promise<bigint> {
    const res = await callProgram(this.client, this.address, "balance_of", [address]);
    return safeBigInt(res.result, "balance");
  }

  async allowance(owner: string, spender: string): Promise<bigint> {
    const res = await callProgram(this.client, this.address, "allowance", [owner, spender]);
    return safeBigInt(res.result, "allowance");
  }

  async transfer(to: string, rawAmount: bigint, opts: TransferOptions = { fee: "5000" }): Promise<string> {
    return this._send("transfer", [to, rawAmount.toString()], opts);
  }

  async grant(spender: string, rawAmount: bigint, opts: TransferOptions = { fee: "5000" }): Promise<string> {
    return this._send("grant", [spender, rawAmount.toString()], opts);
  }

  async pull(from: string, to: string, rawAmount: bigint, opts: TransferOptions = { fee: "5000" }): Promise<string> {
    return this._send("pull", [from, to, rawAmount.toString()], opts);
  }

  private async _send(method: string, params: unknown[], opts: TransferOptions): Promise<string> {
    const nonce = await getNonce(this.client, this.signer.address as string);
    const tx = buildContractCall({
      from: this.signer.address as string,
      contract: this.address,
      method,
      params,
      nonce: nonce + 1,
      fee: opts.fee,
    });
    const signed = await signTx(tx, this.signer);
    return submit(this.client, signed);
  }
}

