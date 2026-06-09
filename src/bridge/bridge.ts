import type { OctraClient } from "../rpc/client.js";

export interface BridgeStatus {
  status: string;
  epoch: number;
  leafCount: number;
  root: string;
}

export interface BridgeHeader {
  epoch: number;
  root: string;
  previousRoot: string;
  timestamp: number;
}

export interface BridgeMessage {
  leafIndex: number;
  sender: string;
  recipient: string;
  amount: string;
  epoch: number;
  txHash: string;
}

export interface BridgeProof {
  leafIndex: number;
  leaf: string;
  proof: string[];
  root: string;
}

export interface BridgeClaimCalldata {
  to: string;
  data: string;
}

export class BridgeClient {
  readonly client: OctraClient;

  constructor(client: OctraClient) {
    this.client = client;
  }

  async status(): Promise<BridgeStatus> {
    return this.client.call("bridge_status", []);
  }

  async header(epoch: number): Promise<BridgeHeader> {
    return this.client.call("bridge_header", [epoch]);
  }

  async messagesByEpoch(epoch: number): Promise<BridgeMessage[]> {
    return this.client.call("bridge_messages_by_epoch", [epoch]);
  }

  async proofByLeafIndex(leafIndex: number): Promise<BridgeProof> {
    return this.client.call("bridge_proof_by_leaf_index", [leafIndex]);
  }

  async claimCalldata(leafIndex: number, recipient: string): Promise<BridgeClaimCalldata> {
    return this.client.call("bridge_claim_calldata", [leafIndex, recipient]);
  }
}
