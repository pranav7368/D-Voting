/**
 * Wire format: JSON <-> crypto types.
 *
 * Big integers travel as base64url-encoded fixed-width byte strings, never as
 * JSON numbers (which would silently lose precision above 2^53) and never as
 * decimal strings (which invite parser divergence between implementations).
 * Fixed width matters because these values are hashed: a variable-length
 * encoding would let two encodings of the same number produce different hashes.
 */

import {
  encodeElement,
  encodeScalar,
  fromBase64Url,
  os2ip,
  toBase64Url,
  type Ciphertext,
  type DisjunctiveProof,
  type DlogEqualityProof,
  type EncryptedBallot,
  type PrimeOrderGroup,
} from "@dvoting/crypto";

export interface WireCiphertext {
  alpha: string;
  beta: string;
}

export interface WireBranch {
  commitment1: string;
  commitment2: string;
  challenge: string;
  response: string;
}

export interface WireBallot {
  electionId: string;
  ballotId: string;
  credentialFingerprint: string;
  choices: WireCiphertext[];
  choiceProofs: { branches: WireBranch[] }[];
  aggregateProof: { branches: WireBranch[] };
}

export class WireError extends Error {
  override name = "WireError";
}

const element = (group: PrimeOrderGroup, value: bigint): string =>
  toBase64Url(encodeElement(group, value));
const scalar = (group: PrimeOrderGroup, value: bigint): string =>
  toBase64Url(encodeScalar(group, value));

export function ciphertextToWire(group: PrimeOrderGroup, ct: Ciphertext): WireCiphertext {
  return { alpha: element(group, ct.alpha), beta: element(group, ct.beta) };
}

export function proofToWire(group: PrimeOrderGroup, proof: DisjunctiveProof) {
  return {
    branches: proof.branches.map((branch) => ({
      commitment1: element(group, branch.commitment1),
      commitment2: element(group, branch.commitment2),
      challenge: scalar(group, branch.challenge),
      response: scalar(group, branch.response),
    })),
  };
}

export function ballotToWire(group: PrimeOrderGroup, ballot: EncryptedBallot): WireBallot {
  return {
    electionId: ballot.electionId,
    ballotId: ballot.ballotId,
    credentialFingerprint: ballot.credentialFingerprint,
    choices: ballot.choices.map((ct) => ciphertextToWire(group, ct)),
    choiceProofs: ballot.choiceProofs.map((proof) => proofToWire(group, proof)),
    aggregateProof: proofToWire(group, ballot.aggregateProof),
  };
}

/**
 * Parse a ballot from untrusted JSON.
 *
 * Range checks happen here so malformed values are rejected before reaching any
 * exponentiation. Subgroup membership is checked later by verifyBallot -- this
 * layer only guarantees the values are well-formed integers of the right size.
 */
export function ballotFromWire(group: PrimeOrderGroup, wire: WireBallot): EncryptedBallot {
  const toElement = (text: string, label: string): bigint => {
    const bytes = decode(text, label);
    if (bytes.length !== group.pByteLength) {
      throw new WireError(`${label}: expected ${group.pByteLength} bytes`);
    }
    const value = os2ip(bytes);
    if (value <= 0n || value >= group.p) throw new WireError(`${label}: out of range`);
    return value;
  };
  const toScalar = (text: string, label: string): bigint => {
    const bytes = decode(text, label);
    if (bytes.length !== group.qByteLength) {
      throw new WireError(`${label}: expected ${group.qByteLength} bytes`);
    }
    const value = os2ip(bytes);
    if (value < 0n || value >= group.q) throw new WireError(`${label}: out of range`);
    return value;
  };

  const branches = (input: { branches: WireBranch[] }, label: string): DisjunctiveProof => {
    if (!Array.isArray(input?.branches) || input.branches.length === 0) {
      throw new WireError(`${label}: missing branches`);
    }
    return {
      branches: input.branches.map((branch, i) => ({
        commitment1: toElement(branch.commitment1, `${label}[${i}].commitment1`),
        commitment2: toElement(branch.commitment2, `${label}[${i}].commitment2`),
        challenge: toScalar(branch.challenge, `${label}[${i}].challenge`),
        response: toScalar(branch.response, `${label}[${i}].response`),
      })),
    };
  };

  if (!Array.isArray(wire.choices) || !Array.isArray(wire.choiceProofs)) {
    throw new WireError("ballot: choices and choiceProofs must be arrays");
  }
  if (wire.choices.length !== wire.choiceProofs.length) {
    throw new WireError("ballot: choice and proof counts differ");
  }

  return {
    electionId: String(wire.electionId),
    ballotId: String(wire.ballotId),
    credentialFingerprint: String(wire.credentialFingerprint),
    choices: wire.choices.map((ct, i) => ({
      alpha: toElement(ct.alpha, `choices[${i}].alpha`),
      beta: toElement(ct.beta, `choices[${i}].beta`),
    })),
    choiceProofs: wire.choiceProofs.map((proof, i) => branches(proof, `choiceProofs[${i}]`)),
    aggregateProof: branches(wire.aggregateProof, "aggregateProof"),
  };
}

export interface WireDlogProof {
  commitment1: string;
  commitment2: string;
  challenge: string;
  response: string;
}

export interface WirePartialDecryption {
  index: number;
  factor: string;
  proof: WireDlogProof;
}

export function partialDecryptionToWire(
  group: PrimeOrderGroup,
  partial: { index: number; factor: bigint; proof: DlogEqualityProof },
): WirePartialDecryption {
  return {
    index: partial.index,
    factor: element(group, partial.factor),
    proof: {
      commitment1: element(group, partial.proof.commitment1),
      commitment2: element(group, partial.proof.commitment2),
      challenge: scalar(group, partial.proof.challenge),
      response: scalar(group, partial.proof.response),
    },
  };
}

export function partialDecryptionFromWire(
  group: PrimeOrderGroup,
  wire: WirePartialDecryption,
): { index: number; factor: bigint; proof: DlogEqualityProof } {
  const toElement = (text: string, label: string): bigint => {
    const bytes = decode(text, label);
    if (bytes.length !== group.pByteLength) throw new WireError(`${label}: wrong length`);
    const value = os2ip(bytes);
    if (value <= 0n || value >= group.p) throw new WireError(`${label}: out of range`);
    return value;
  };
  const toScalar = (text: string, label: string): bigint => {
    const bytes = decode(text, label);
    if (bytes.length !== group.qByteLength) throw new WireError(`${label}: wrong length`);
    const value = os2ip(bytes);
    if (value < 0n || value >= group.q) throw new WireError(`${label}: out of range`);
    return value;
  };

  if (!Number.isInteger(wire?.index) || wire.index < 1) {
    throw new WireError("partialDecryption.index must be a positive integer");
  }
  return {
    index: wire.index,
    factor: toElement(wire.factor, "partialDecryption.factor"),
    proof: {
      commitment1: toElement(wire.proof?.commitment1, "partialDecryption.proof.commitment1"),
      commitment2: toElement(wire.proof?.commitment2, "partialDecryption.proof.commitment2"),
      challenge: toScalar(wire.proof?.challenge, "partialDecryption.proof.challenge"),
      response: toScalar(wire.proof?.response, "partialDecryption.proof.response"),
    },
  };
}

export interface WireAuditSecret {
  ballotId: string;
  selections: number[];
  randomness: string[];
}

export function auditSecretToWire(
  group: PrimeOrderGroup,
  secret: { ballotId: string; selections: readonly number[]; randomness: readonly bigint[] },
): WireAuditSecret {
  return {
    ballotId: secret.ballotId,
    selections: [...secret.selections],
    randomness: secret.randomness.map((r) => scalar(group, r)),
  };
}

export function auditSecretFromWire(group: PrimeOrderGroup, wire: WireAuditSecret) {
  if (!Array.isArray(wire?.selections) || !Array.isArray(wire?.randomness)) {
    throw new WireError("auditSecret: selections and randomness must be arrays");
  }
  return {
    ballotId: String(wire.ballotId),
    selections: wire.selections.map((s) => {
      if (s !== 0 && s !== 1) throw new WireError("auditSecret: selection must be 0 or 1");
      return s;
    }),
    randomness: wire.randomness.map((text, i) => {
      const bytes = decode(text, `auditSecret.randomness[${i}]`);
      if (bytes.length !== group.qByteLength) {
        throw new WireError(`auditSecret.randomness[${i}]: wrong length`);
      }
      const value = os2ip(bytes);
      if (value <= 0n || value >= group.q) {
        throw new WireError(`auditSecret.randomness[${i}]: out of range`);
      }
      return value;
    }),
  };
}

function decode(text: unknown, label: string): Uint8Array {
  if (typeof text !== "string") throw new WireError(`${label}: expected a string`);
  try {
    return fromBase64Url(text);
  } catch {
    throw new WireError(`${label}: not valid base64url`);
  }
}
