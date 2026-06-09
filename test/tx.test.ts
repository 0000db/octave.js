import { describe, it, expect } from "vitest";
import { canonicalJson } from "../src/tx/canonical.js";
import {
  buildTransfer,
  buildContractCall,
  signTxWithKey,
  txHash,
} from "../src/tx/builder.js";
import { makeKeypair, verifySignature, base64Decode } from "../src/crypto/index.js";
import type { UnsignedTransaction } from "../src/tx/canonical.js";

describe("canonicalJson", () => {
  it("produces deterministic output with fixed field order", () => {
    const tx: UnsignedTransaction = {
      from: "octABC",
      to_: "octDEF",
      amount: "1000000",
      nonce: 1,
      ou: "200000",
      timestamp: 1703000000,
      op_type: "standard",
    };
    const json = canonicalJson(tx);
    expect(json).toBe(
      '{"from":"octABC","to_":"octDEF","amount":"1000000","nonce":1,"ou":"200000","timestamp":1703000000,"op_type":"standard"}',
    );
  });

  it("includes optional encrypted_data when present", () => {
    const tx: UnsignedTransaction = {
      from: "octA",
      to_: "octB",
      amount: "0",
      nonce: 1,
      ou: "5000",
      timestamp: 1703000000,
      op_type: "encrypt",
      encrypted_data: "base64payload==",
    };
    const json = canonicalJson(tx);
    expect(json).toContain('"encrypted_data":"base64payload=="');
    expect(json.indexOf("encrypted_data")).toBeGreaterThan(json.indexOf("op_type"));
  });

  it("includes optional message when present", () => {
    const tx: UnsignedTransaction = {
      from: "octA",
      to_: "octB",
      amount: "0",
      nonce: 1,
      ou: "5000",
      timestamp: 1703000000,
      op_type: "standard",
      message: "hello world",
    };
    const json = canonicalJson(tx);
    expect(json).toContain('"message":"hello world"');
  });

  it("escapes special characters in string fields", () => {
    const tx: UnsignedTransaction = {
      from: 'oct"test',
      to_: "octB",
      amount: "0",
      nonce: 1,
      ou: "5000",
      timestamp: 1703000000,
      op_type: "standard",
    };
    const json = canonicalJson(tx);
    expect(json).toContain('"from":"oct\\"test"');
  });

  it("omits encrypted_data and message when absent", () => {
    const tx: UnsignedTransaction = {
      from: "octA",
      to_: "octB",
      amount: "5000000",
      nonce: 2,
      ou: "200000",
      timestamp: 1703000001,
      op_type: "standard",
    };
    const json = canonicalJson(tx);
    expect(json).not.toContain("encrypted_data");
    expect(json).not.toContain("message");
  });
});

describe("buildTransfer", () => {
  it("builds correct unsigned tx", () => {
    const tx = buildTransfer({
      from: "octSender",
      to: "octRecipient",
      amount: 5_000_000n,
      nonce: 3,
      fee: "200000",
      timestamp: 1703000000,
    });
    expect(tx.from).toBe("octSender");
    expect(tx.to_).toBe("octRecipient");
    expect(tx.amount).toBe("5000000");
    expect(tx.nonce).toBe(3);
    expect(tx.ou).toBe("200000");
    expect(tx.op_type).toBe("standard");
    expect(tx.timestamp).toBe(1703000000);
  });
});

describe("buildContractCall", () => {
  it("sets op_type to contract_call", () => {
    const tx = buildContractCall({
      from: "octCaller",
      contract: "octContract",
      method: "increment",
      params: [],
      nonce: 1,
      fee: "5000",
      timestamp: 1703000000,
    });
    expect(tx.op_type).toBe("contract_call");
    expect(tx.to_).toBe("octContract");
  });
});

describe("txHash", () => {
  it("is deterministic for the same tx", async () => {
    const tx: UnsignedTransaction = {
      from: "octA",
      to_: "octB",
      amount: "1000000",
      nonce: 1,
      ou: "200000",
      timestamp: 1703000000,
      op_type: "standard",
    };
    const h1 = await txHash(tx);
    const h2 = await txHash(tx);
    expect(h1).toBe(h2);
    expect(h1).toHaveLength(64);
  });

  it("differs for different transactions", async () => {
    const base: UnsignedTransaction = {
      from: "octA",
      to_: "octB",
      amount: "1000000",
      nonce: 1,
      ou: "200000",
      timestamp: 1703000000,
      op_type: "standard",
    };
    const modified = { ...base, nonce: 2 };
    const h1 = await txHash(base);
    const h2 = await txHash(modified);
    expect(h1).not.toBe(h2);
  });
});

describe("signTxWithKey", () => {
  it("produces a signed transaction with valid Ed25519 signature", async () => {
    const seed = new Uint8Array(32).fill(11);
    const kp = await makeKeypair(seed);

    const tx: UnsignedTransaction = {
      from: kp.address as string,
      to_: "octRecipient",
      amount: "1000000",
      nonce: 1,
      ou: "200000",
      timestamp: 1703000000,
      op_type: "standard",
    };

    const signed = await signTxWithKey(tx, kp.signingKey, kp.publicKey);
    expect(typeof signed.signature).toBe("string");
    expect(typeof signed.public_key).toBe("string");

    const canonical = canonicalJson(tx);
    const msgBytes = new TextEncoder().encode(canonical);
    const sigBytes = base64Decode(signed.signature);
    const pubBytes = base64Decode(signed.public_key);

    const valid = await verifySignature(msgBytes, sigBytes, pubBytes);
    expect(valid).toBe(true);
  });
});
