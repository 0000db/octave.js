export class OctraError extends Error {
  constructor(message: string) {
    super(message);
    this.name = this.constructor.name;
  }
}

export class OctraRpcError extends OctraError {
  constructor(
    public readonly code: number,
    message: string,
    public readonly data?: unknown,
  ) {
    super(message);
  }
}

export class OctraSubmitError extends OctraError {
  constructor(public readonly reason: string) {
    super(`Transaction submission failed: ${reason}`);
  }
}

export class OctraSignError extends OctraError {
  constructor(message = "Signing failed") {
    super(message);
  }
}

export class OctraValidationError extends OctraError {
  constructor(
    public readonly field: string,
    public readonly reason: string,
  ) {
    super(`Validation error on field '${field}': ${reason}`);
  }
}

export class OctraProofError extends OctraError {
  constructor(message = "PVAC runtime unavailable or proof generation failed") {
    super(message);
  }
}
