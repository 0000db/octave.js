import { OCT_DECIMALS, OCT_UNIT } from "../core/constants.js";
import { OctraValidationError } from "../core/errors.js";
import type { RawAmount } from "../core/types.js";
import { asRawAmount } from "../core/types.js";

export function parseOct(humanString: string): RawAmount {
  const trimmed = humanString.trim();
  if (!/^\d+(\.\d+)?$/.test(trimmed)) {
    throw new OctraValidationError("amount", `Invalid OCT amount: "${humanString}"`);
  }

  const [intPart, fracPart = ""] = trimmed.split(".");
  if (fracPart.length > OCT_DECIMALS) {
    throw new OctraValidationError(
      "amount",
      `OCT amount has ${fracPart.length} fractional digits, max is ${OCT_DECIMALS}: "${humanString}"`,
    );
  }
  const paddedFrac = fracPart.padEnd(OCT_DECIMALS, "0");

  const raw = BigInt(intPart!) * OCT_UNIT + BigInt(paddedFrac);
  return asRawAmount(raw);
}

export function formatOct(rawAmount: bigint): string {
  const isNeg = rawAmount < 0n;
  const abs = isNeg ? -rawAmount : rawAmount;

  const intPart = abs / OCT_UNIT;
  const fracPart = abs % OCT_UNIT;

  const fracStr = fracPart.toString().padStart(OCT_DECIMALS, "0");
  const trimmed = fracStr.replace(/0+$/, "");

  const formatted = trimmed.length > 0 ? `${intPart}.${trimmed}` : `${intPart}`;
  return isNeg ? `-${formatted}` : formatted;
}

export function parseOu(ouString: string): string {
  const trimmed = ouString.trim();
  if (!/^\d+$/.test(trimmed)) {
    throw new OctraValidationError("ou", `Invalid ou amount: "${ouString}"`);
  }
  return trimmed;
}

export function parseToken(humanAmount: string, decimals: number): bigint {
  const trimmed = humanAmount.trim();
  if (!/^\d+(\.\d+)?$/.test(trimmed)) {
    throw new OctraValidationError("amount", `Invalid token amount: "${humanAmount}"`);
  }

  const [intPart, fracPart = ""] = trimmed.split(".");
  if (fracPart.length > decimals) {
    throw new OctraValidationError(
      "amount",
      `Token amount has ${fracPart.length} fractional digits, max is ${decimals}: "${humanAmount}"`,
    );
  }
  const unit = 10n ** BigInt(decimals);
  const paddedFrac = fracPart.padEnd(decimals, "0");
  return BigInt(intPart!) * unit + (paddedFrac.length > 0 ? BigInt(paddedFrac) : 0n);
}

export function formatToken(rawAmount: bigint, decimals: number): string {
  const unit = 10n ** BigInt(decimals);
  const isNeg = rawAmount < 0n;
  const abs = isNeg ? -rawAmount : rawAmount;

  const intPart = abs / unit;
  const fracPart = abs % unit;

  const fracStr = fracPart.toString().padStart(decimals, "0");
  const trimmed = fracStr.replace(/0+$/, "");

  const formatted = trimmed.length > 0 ? `${intPart}.${trimmed}` : `${intPart}`;
  return isNeg ? `-${formatted}` : formatted;
}
