export { OctraClient } from "./client.js";
export type { OctraClientOptions } from "./client.js";

export { getVersion, getStatus, getStats, getMetrics } from "./node.js";
export type { NodeVersion, NodeStatus, NodeStats, NodeMetrics } from "./node.js";

export {
  getBalance, getAccount, getNonce, getPublicKey, validateAddress, getSupply,
} from "./accounts.js";
export type {
  BalanceResult, AccountResult, NonceResult, PublicKeyResult,
  ValidateAddressResult, SupplyResult,
} from "./accounts.js";

export {
  submit, submitBatch, getTransaction, getRecentTransactions, getTransactions,
  getTransactionsByAddress, getTransactionsByEpoch, getTotalTransactions, search,
} from "./transactions.js";
export type {
  TxStatus, SubmitResult, TransactionResult, TransactionListResult,
  TotalTransactionsResult, SearchResult,
} from "./transactions.js";

export { getCurrentEpoch, getEpoch, listEpochs, getEpochSummaries } from "./epochs.js";
export type { EpochResult, CurrentEpochResult, EpochListResult } from "./epochs.js";

export {
  getRecommendedFee, getStagingView, getStagingStats, estimateOu, removeStagingTx,
} from "./fees.js";
export type {
  RecommendedFeeResult, StagingViewResult, StagingStatsResult, EstimateOuResult,
} from "./fees.js";

export {
  getProgram, getAbi, getStorage, listPrograms, getReceipt, callProgram, computeProgramAddress,
} from "./programs.js";
export type {
  ProgramMetadata, ProgramAbi, ProgramStorageResult, ProgramListResult,
  ContractReceiptResult, ContractCallResult, ComputeAddressResult,
} from "./programs.js";

export { compileAssembly, compileAml, compileAmlMulti } from "./compilation.js";
export type { CompileResult } from "./compilation.js";

export { verifySource, saveAbi, getSource } from "./source.js";
export type { VerifySourceResult, SourceResult } from "./source.js";

export {
  registerPublicKey, registerPvacPubkey, getPvacPubkey,
  getEncryptedCipher, getEncryptedBalance,
} from "./fhe.js";
export type {
  RegisterPublicKeyResult, PvacPubkeyResult, EncryptedCipherResult, EncryptedBalanceResult,
} from "./fhe.js";

export { getViewPubkey, getStealthOutputs } from "./stealth.js";
export type { ViewPubkeyResult, StealthOutput, StealthOutputsResult } from "./stealth.js";

export { getTokensByAddress, getTokenTransfersByAddress } from "./tokens.js";
export type { TokenBalance, TokenTransfer, TokenTransfersResult } from "./tokens.js";

export { getCircleInfo, getCircleAsset, getCircleAssetCiphertext, getCircleAssetCiphertextByKey } from "./circles.js";
export type { CircleInfo, CircleAssetResult, CircleCiphertextResult } from "./circles.js";

export { signAndSend } from "./signer.js";
export type { SendTransferParams } from "./signer.js";
