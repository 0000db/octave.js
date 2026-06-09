import { sha256 } from "../crypto/hash.js";
import { base58Encode, base64Encode, hexEncode } from "../crypto/encoding.js";
import type { OctraClient } from "../rpc/client.js";
import type { Signer } from "../core/types.js";
import { ADDRESS_B58_LENGTH } from "../core/constants.js";
import { getNonce } from "../rpc/accounts.js";
import { submit } from "../rpc/transactions.js";
import { getCircleInfo, getCircleAsset, getCircleAssetCiphertextByKey } from "../rpc/circles.js";
import { buildRaw, signTx } from "../tx/builder.js";
import { deriveReadKey, sealAsset, unsealAsset, computeResourceKey } from "./sealer.js";
import type { PaddingClass } from "./sealer.js";
import type { CircleInfo, CircleAssetResult } from "../rpc/circles.js";

export interface CircleDeployConfig {
  runtime: string;
  privacyClass: string;
  browserMode: string;
  resourceMode: string;
  codeB64?: string;
  policyHash?: string;
  membersRoot?: string;
  exportPolicy?: string;
  limits?: {
    maxStableBytes?: string;
    maxAssetsBytes?: string;
    maxInlineValue?: string;
    maxWasmBytes?: string;
  };
}

export interface UploadSealedOptions {
  keyId?: string;
  paddingClass?: PaddingClass;
  fee: string;
}

function defaultLimits() {
  return {
    max_stable_bytes: "33554432",
    max_assets_bytes: "33554432",
    max_inline_value: "65536",
    max_wasm_bytes: "33554432",
  };
}

function configToPayload(config: CircleDeployConfig): object {
  const payload: Record<string, unknown> = {
    runtime: config.runtime,
    privacy_class: config.privacyClass,
    browser_mode: config.browserMode,
    resource_mode: config.resourceMode,
    code_b64: config.codeB64 ?? null,
    policy_hash: config.policyHash ?? null,
    members_root: config.membersRoot ?? null,
    export_policy: config.exportPolicy ?? null,
    limits: {
      max_stable_bytes: config.limits?.maxStableBytes ?? "33554432",
      max_assets_bytes: config.limits?.maxAssetsBytes ?? "33554432",
      max_inline_value: config.limits?.maxInlineValue ?? "65536",
      max_wasm_bytes: config.limits?.maxWasmBytes ?? "33554432",
    },
  };
  return payload;
}

export async function computeCircleId(deployerAddress: string, nonce: number, config: CircleDeployConfig): Promise<string> {
  const enc = new TextEncoder();
  const payload = configToPayload(config);
  const payloadJson = JSON.stringify(payload);

  const payloadHashInput = enc.encode(`octra:circle_deploy_payload:v1${payloadJson}`);
  const payloadHash = hexEncode(await sha256(payloadHashInput));

  const seedInput = enc.encode(`octra:circle_deploy_id:v1${deployerAddress}${nonce}${payloadHash}`);
  const seed = await sha256(seedInput);

  let b58 = base58Encode(seed);
  while (b58.length < ADDRESS_B58_LENGTH) b58 = "1" + b58;
  return "oct" + b58;
}

export class CircleDeployer {
  readonly client: OctraClient;
  readonly signer: Signer;

  constructor(client: OctraClient, signer: Signer) {
    this.client = client;
    this.signer = signer;
  }

  static defaultSealedConfig(): CircleDeployConfig {
    return {
      runtime: "octb",
      privacyClass: "sealed",
      browserMode: "native_sealed",
      resourceMode: "sealed_read",
    };
  }

  async deploy(config: CircleDeployConfig, opts: { fee: string }): Promise<{ circleId: string; txHash: string }> {
    const nonce = await getNonce(this.client, this.signer.address as string);
    const nextNonce = nonce + 1;
    const circleId = await computeCircleId(this.signer.address as string, nextNonce, config);
    const payload = configToPayload(config);

    const tx = buildRaw({
      from: this.signer.address as string,
      to_: circleId,
      amount: "0",
      nonce: nextNonce,
      ou: opts.fee,
      op_type: "deploy_circle",
      message: JSON.stringify(payload),
    });

    const signed = await signTx(tx, this.signer);
    const hash = await submit(this.client, signed);
    return { circleId, txHash: hash };
  }
}

export class CircleAssetUploader {
  readonly client: OctraClient;
  readonly signer: Signer;

  constructor(client: OctraClient, signer: Signer) {
    this.client = client;
    this.signer = signer;
  }

  async uploadSealed(
    circleId: string,
    path: string,
    plaintext: Uint8Array,
    contentType: string,
    passphrase: string,
    opts: UploadSealedOptions,
  ): Promise<string> {
    const canonicalPath = path.startsWith("/") ? path : `/${path}`;
    const keyId = opts.keyId ?? "default";
    const readKey = await deriveReadKey(circleId, keyId, passphrase);
    const { ciphertext, plaintextHash } = await sealAsset(plaintext, readKey, opts.paddingClass);

    const metadata = JSON.stringify({
      path: canonicalPath,
      content_type: contentType,
      key_id: keyId,
      plaintext_hash: plaintextHash,
      encoding: "identity",
      ...(opts.paddingClass ? { padding_class: opts.paddingClass } : {}),
    });

    const nonce = await getNonce(this.client, this.signer.address as string);
    const tx = buildRaw({
      from: this.signer.address as string,
      to_: circleId,
      amount: "0",
      nonce: nonce + 1,
      ou: opts.fee,
      op_type: "circle_asset_put_encrypted",
      encrypted_data: base64Encode(ciphertext),
      message: metadata,
    });

    const signed = await signTx(tx, this.signer);
    return submit(this.client, signed);
  }
}

export class CircleReader {
  readonly client: OctraClient;

  constructor(client: OctraClient) {
    this.client = client;
  }

  async getInfo(circleId: string): Promise<CircleInfo> {
    return getCircleInfo(this.client, circleId);
  }

  async getAsset(circleId: string, path: string): Promise<CircleAssetResult> {
    return getCircleAsset(this.client, circleId, path);
  }

  async getSealedAsset(
    circleId: string,
    path: string,
    passphrase: string,
    keyId = "default",
  ): Promise<Uint8Array> {
    const canonicalPath = path.startsWith("/") ? path : `/${path}`;
    const resourceKey = await computeResourceKey(circleId, canonicalPath);
    const res = await getCircleAssetCiphertextByKey(this.client, circleId, resourceKey);

    if (!res.ciphertext_b64) throw new Error("No ciphertext returned by node");
    const ciphertext = Uint8Array.from(atob(res.ciphertext_b64), (c) => c.charCodeAt(0));
    const resolvedKeyId = res.key_id ?? keyId;
    const readKey = await deriveReadKey(circleId, resolvedKeyId, passphrase);

    return unsealAsset(ciphertext, readKey, res.plaintext_hash);
  }
}
