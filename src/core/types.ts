declare const brand: unique symbol;
type Brand<T, B> = T & { readonly [brand]: B };

export type Address = Brand<string, "Address">;
export type TxHash = Brand<string, "TxHash">;
export type RawAmount = Brand<bigint, "RawAmount">;
export type OuAmount = Brand<string, "OuAmount">;
export type Base64 = Brand<string, "Base64">;
export type HexString = Brand<string, "HexString">;

export function asAddress(s: string): Address { return s as Address; }
export function asTxHash(s: string): TxHash { return s as TxHash; }
export function asRawAmount(n: bigint): RawAmount { return n as RawAmount; }
export function asOuAmount(s: string): OuAmount { return s as OuAmount; }
export function asBase64(s: string): Base64 { return s as Base64; }
export function asHexString(s: string): HexString { return s as HexString; }

export interface Signer {
  readonly address: Address;
  readonly publicKeyBytes: Uint8Array;
  sign(message: Uint8Array): Promise<Uint8Array>;
}

export interface Keypair {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
  address: Address;
}

export type OpType =
  | "standard"
  | "contract_call"
  | "deploy"
  | "deploy_circle"
  | "circle_asset_put_encrypted"
  | "encrypt"
  | "decrypt"
  | "stealth"
  | "stealth_claim"
  | "key_switch"
  | "register_pubkey"
  | "register_pvac";
