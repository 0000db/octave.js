export const OCT_DECIMALS = 6;
export const OCT_UNIT = 1_000_000n;
export const ADDRESS_PREFIX = "oct";
export const ADDRESS_B58_LENGTH = 44;
export const ADDRESS_TOTAL_LENGTH = 47;
export const HD_KEY = "Octra seed";

export const OP_TYPE = {
  STANDARD: "standard",
  CONTRACT_CALL: "contract_call",
  DEPLOY: "deploy",
  DEPLOY_CIRCLE: "deploy_circle",
  CIRCLE_ASSET_PUT_ENCRYPTED: "circle_asset_put_encrypted",
  ENCRYPT: "encrypt",
  DECRYPT: "decrypt",
  STEALTH: "stealth",
  STEALTH_CLAIM: "stealth_claim",
  KEY_SWITCH: "key_switch",
  REGISTER_PUBKEY: "register_pubkey",
  REGISTER_PVAC: "register_pvac",
} as const;

export const KEYSTORE_PBKDF2_ITERATIONS = 600_000;
export const MNEMONIC_PBKDF2_ITERATIONS = 2048;
