import type { OctraClient } from "./client.js";

export interface NodeVersion {
  version: string;
  protocol?: string;
  [key: string]: unknown;
}

export interface NodeStatus {
  epoch?: number;
  validator?: string;
  timestamp?: number;
  network_version?: string;
  [key: string]: unknown;
}

export interface NodeStats {
  accounts?: number;
  total_supply?: string;
  transactions?: number;
  [key: string]: unknown;
}

export interface NodeMetrics {
  [key: string]: unknown;
}

export async function getVersion(client: OctraClient): Promise<NodeVersion> {
  return client.call<NodeVersion>("node_version");
}

export async function getStatus(client: OctraClient): Promise<NodeStatus> {
  return client.call<NodeStatus>("node_status");
}

export async function getStats(client: OctraClient): Promise<NodeStats> {
  return client.call<NodeStats>("node_stats");
}

export async function getMetrics(client: OctraClient): Promise<NodeMetrics> {
  return client.call<NodeMetrics>("node_metrics");
}
