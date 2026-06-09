// Core types and errors
export type { Address, TxHash, RawAmount, OuAmount, Base64, HexString, Signer, Keypair, OpType } from "./core/types.js";
export { asAddress, asTxHash, asRawAmount, asOuAmount, asBase64, asHexString } from "./core/types.js";
export {
  OctraError, OctraRpcError, OctraSubmitError, OctraSignError,
  OctraValidationError, OctraProofError,
} from "./core/errors.js";
export {
  OCT_DECIMALS, OCT_UNIT, ADDRESS_PREFIX, ADDRESS_B58_LENGTH, ADDRESS_TOTAL_LENGTH,
  HD_KEY, OP_TYPE, KEYSTORE_PBKDF2_ITERATIONS, MNEMONIC_PBKDF2_ITERATIONS,
} from "./core/constants.js";

// Crypto
export {
  sha256, hmacSha512, pbkdf2Sha256, pbkdf2Sha512,
  base58Encode, base58Decode,
  base64Encode, base64Decode, base64UrlEncode, base64UrlDecode,
  hexEncode, hexDecode,
  keypairFromSeed, makeKeypair, generateKeypair,
  signBytes, verifySignature, getSigningKey, deriveAddress,
  ed25519SeedToX25519PrivateKey, ed25519PubToX25519, x25519DeriveShared,
  deriveHdSeed,
  generateMnemonic, validateMnemonic, mnemonicToSeed,
  BIP39_WORDLIST,
} from "./crypto/index.js";

// Transactions
export type { UnsignedTransaction, SignedTransaction } from "./tx/index.js";
export {
  canonicalJson,
  buildTransfer, buildContractCall, buildDeploy, buildRegisterPublicKey, buildRaw,
  signTx, signTxWithKey, txHash,
} from "./tx/index.js";
export type { TransferParams, ContractCallParams, DeployParams, RegisterPublicKeyParams } from "./tx/index.js";

// Wallet
export { Wallet } from "./wallet/index.js";
export { encryptKeystore, decryptKeystore, serializeKeystore, deserializeKeystore } from "./wallet/index.js";
export type { KeystoreData } from "./wallet/index.js";

// RPC
export { OctraClient } from "./rpc/index.js";
export type { OctraClientOptions } from "./rpc/index.js";
export {
  getVersion, getStatus, getStats, getMetrics,
  getBalance, getAccount, getNonce, getPublicKey, validateAddress, getSupply,
  submit, submitBatch, getTransaction, getRecentTransactions, getTransactions,
  getTransactionsByAddress, getTransactionsByEpoch, getTotalTransactions, search,
  getCurrentEpoch, getEpoch, listEpochs, getEpochSummaries,
  getRecommendedFee, getStagingView, getStagingStats, estimateOu, removeStagingTx,
  getProgram, getAbi, getStorage, listPrograms, getReceipt, callProgram, computeProgramAddress,
  compileAssembly, compileAml, compileAmlMulti,
  verifySource, saveAbi, getSource,
  registerPublicKey, registerPvacPubkey, getPvacPubkey, getEncryptedCipher, getEncryptedBalance,
  getViewPubkey, getStealthOutputs,
  getTokensByAddress, getTokenTransfersByAddress,
  getCircleInfo, getCircleAsset, getCircleAssetCiphertext, getCircleAssetCiphertextByKey,
  signAndSend,
} from "./rpc/index.js";

// Units
export { parseOct, formatOct, parseOu, parseToken, formatToken } from "./units/index.js";

// Program
export { Program, compileProgram, compileProgramMulti, deployProgram } from "./program/index.js";
export type { SendCallOptions, DeployOptions } from "./program/index.js";

// Token (OCS-01)
export { Ocs01Token } from "./token/index.js";
export type { TokenMetadata, TransferOptions } from "./token/index.js";

// Circle
export {
  OctUri,
  deriveReadKey, computeResourceKey, sealAsset, unsealAsset,
  computeCircleId, CircleDeployer, CircleAssetUploader, CircleReader,
} from "./circle/index.js";
export type { PaddingClass, CircleDeployConfig, UploadSealedOptions } from "./circle/index.js";

// Bridge
export { BridgeClient } from "./bridge/index.js";
export type { BridgeStatus, BridgeHeader, BridgeMessage, BridgeProof, BridgeClaimCalldata } from "./bridge/index.js";
