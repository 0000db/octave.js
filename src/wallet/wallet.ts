import { makeKeypair, getSigningKey, signBytes } from "../crypto/keypair.js";
import { deriveHdSeed } from "../crypto/hd.js";
import { mnemonicToSeed, validateMnemonic, generateMnemonic12Async } from "../crypto/mnemonic.js";
import { base64Encode, base64Decode } from "../crypto/encoding.js";
import { serializeKeystore, deserializeKeystore } from "./keystore.js";
import type { Keypair, Address, Signer } from "../core/types.js";
import { OctraValidationError } from "../core/errors.js";

export class Wallet implements Signer {
  readonly address: Address;
  readonly publicKeyBytes: Uint8Array;
  readonly keypair: Keypair;
  private readonly _signingKey: CryptoKey;

  readonly masterSeed?: Uint8Array;
  readonly hdIndex: number;
  readonly hdVersion: 1 | 2;
  readonly mnemonic?: string;

  private constructor(
    keypair: Keypair,
    signingKey: CryptoKey,
    opts?: {
      masterSeed?: Uint8Array;
      hdIndex?: number;
      hdVersion?: 1 | 2;
      mnemonic?: string;
    },
  ) {
    this.keypair = keypair;
    this._signingKey = signingKey;
    this.address = keypair.address;
    this.publicKeyBytes = keypair.publicKey;
    this.masterSeed = opts?.masterSeed;
    this.hdIndex = opts?.hdIndex ?? 0;
    this.hdVersion = opts?.hdVersion ?? 2;
    this.mnemonic = opts?.mnemonic;
  }

  async sign(message: Uint8Array): Promise<Uint8Array> {
    return signBytes(message, this._signingKey);
  }

  static async fromSeed(seed32: Uint8Array): Promise<Wallet> {
    const kp = await makeKeypair(seed32);
    return new Wallet(kp, kp.signingKey);
  }

  static async fromPrivateKey(privKeyBase64: string): Promise<Wallet> {
    const raw = base64Decode(privKeyBase64.trim());
    let seed32: Uint8Array;
    if (raw.length >= 64) {
      seed32 = raw.slice(0, 32);
    } else if (raw.length >= 32) {
      seed32 = raw.slice(0, 32);
    } else {
      throw new OctraValidationError("privKeyBase64", "Private key must be at least 32 bytes");
    }
    const kp = await makeKeypair(seed32);
    return new Wallet(kp, kp.signingKey);
  }

  static async fromMnemonic(mnemonic: string, hdVersion: 1 | 2 = 2, hdIndex = 0): Promise<Wallet> {
    if (!(await validateMnemonic(mnemonic))) {
      throw new OctraValidationError("mnemonic", "Invalid BIP39 mnemonic");
    }
    const masterSeed = await mnemonicToSeed(mnemonic);
    const childSeed = await deriveHdSeed(masterSeed, hdIndex, hdVersion);
    const kp = await makeKeypair(childSeed);
    return new Wallet(kp, kp.signingKey, {
      masterSeed,
      hdIndex,
      hdVersion,
      mnemonic,
    });
  }

  static async generate(): Promise<Wallet> {
    const mnemonic = await generateMnemonic12Async();
    return Wallet.fromMnemonic(mnemonic, 2, 0);
  }

  async deriveHdAccount(index: number, hdVersion?: 1 | 2): Promise<Wallet> {
    if (!this.masterSeed) {
      throw new OctraValidationError("masterSeed", "Wallet has no master seed; cannot derive HD accounts");
    }
    const version = hdVersion ?? this.hdVersion;
    const childSeed = await deriveHdSeed(this.masterSeed, index, version);
    const kp = await makeKeypair(childSeed);
    return new Wallet(kp, kp.signingKey, {
      masterSeed: this.masterSeed,
      hdIndex: index,
      hdVersion: version,
      mnemonic: this.mnemonic,
    });
  }

  async toKeystore(pin: string, rpcUrl = ""): Promise<Uint8Array> {
    const data = {
      priv: base64Encode(this.keypair.secretKey),
      addr: this.keypair.address as string,
      rpc: rpcUrl,
      ...(this.masterSeed
        ? {
            master_seed: base64Encode(this.masterSeed),
            hd_index: this.hdIndex,
            hd_version: this.hdVersion,
            ...(this.mnemonic ? { mnemonic: this.mnemonic } : {}),
          }
        : {}),
    };
    return serializeKeystore(data, pin);
  }

  static async fromKeystore(raw: Uint8Array, pin: string): Promise<Wallet> {
    const data = await deserializeKeystore(raw, pin);

    const rawKey = base64Decode(data.priv);
    let seed32: Uint8Array;
    if (rawKey.length >= 64) {
      seed32 = rawKey.slice(0, 32);
    } else if (rawKey.length >= 32) {
      seed32 = rawKey.slice(0, 32);
    } else {
      throw new OctraValidationError("priv", "Invalid private key in keystore");
    }

    const kp = await makeKeypair(seed32);

    const masterSeed = data.master_seed ? base64Decode(data.master_seed) : undefined;
    const hdVersion = (data.hd_version === 1 || data.hd_version === 2) ? data.hd_version : 2;

    return new Wallet(kp, kp.signingKey, {
      masterSeed,
      hdIndex: data.hd_index ?? 0,
      hdVersion,
      mnemonic: data.mnemonic,
    });
  }

  get privateKeyBase64(): string {
    return base64Encode(this.keypair.secretKey);
  }

  get publicKeyBase64(): string {
    return base64Encode(this.keypair.publicKey);
  }
}
