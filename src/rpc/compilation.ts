import type { OctraClient } from "./client.js";

export interface CompileResult {
  bytecode_b64?: string;
  abi?: unknown;
  instruction_count?: number;
  size?: number;
  version?: string;
  disassembly?: string;
  [key: string]: unknown;
}

export async function compileAssembly(
  client: OctraClient,
  source: string,
): Promise<CompileResult> {
  return client.call<CompileResult>("octra_compileAssembly", [source]);
}

export async function compileAml(
  client: OctraClient,
  source: string,
): Promise<CompileResult> {
  return client.call<CompileResult>("octra_compileAml", [source]);
}

export async function compileAmlMulti(
  client: OctraClient,
  files: Record<string, string>,
  main: string,
): Promise<CompileResult> {
  return client.call<CompileResult>("octra_compileAmlMulti", [{ files, main }]);
}
