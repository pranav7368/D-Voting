/**
 * @dvoting/crypto -- isomorphic cryptographic primitives for D-Voting.
 *
 * This entry point is safe to bundle into the voter app and the public portal:
 * it depends only on WebCrypto globals and native BigInt, with no third-party
 * crypto dependencies and no Node built-ins. Server-only key generation lives
 * behind the separate "@dvoting/crypto/keygen" entry point.
 *
 * Contents:
 *   - RSA blind signatures (RFC 9474) for anonymous voting credentials
 *   - Exponential ElGamal for additively homomorphic ballot encryption
 *   - Disjunctive Chaum-Pedersen zero-knowledge proofs of ballot validity
 *   - Shamir secret sharing + threshold ElGamal decryption with proofs
 */

export {
  concatBytes,
  constantTimeEqual,
  fromBase64Url,
  i2osp,
  os2ip,
  randomBytes,
  toBase64Url,
  utf8,
  xorBytes,
} from "./util/bytes.ts";

export {
  FixedBaseExponentiator,
  bitLength,
  byteLength,
  egcd,
  jacobiSymbol,
  mod,
  modInverse,
  modPow,
  randomBigIntBelow,
} from "./util/bigint.ts";

export { HASH_OUTPUT_BYTES, digest, mgf1, type HashAlgorithm } from "./hash.ts";

export { PssError, emsaPssEncode, emsaPssVerify, type PssParams } from "./pss.ts";

export {
  BlindRsaError,
  MIN_MODULUS_BITS,
  RSABSSA_SHA384_PSS_DETERMINISTIC,
  type BlindResult,
  type BlindRsaPrivateKey,
  type BlindRsaPublicKey,
  type BlindRsaSuite,
  type BlindRsaVariant,
} from "./blind-rsa/types.ts";

export { blind, finalize, generateCredential, verify } from "./blind-rsa/client.ts";

export {
  LocalBlindSigner,
  assertKeyPairConsistent,
  computeKeyId,
  type BlindSigner,
} from "./blind-rsa/issuer.ts";

// --- ElGamal ---------------------------------------------------------------

export {
  DEFAULT_GROUP,
  GroupError,
  MODP_2048,
  MODP_3072,
  assertInSubgroup,
  assertScalar,
  clearFixedBaseCache,
  encodeElement,
  encodeScalar,
  groupExp,
  groupExpFixed,
  groupInv,
  groupMul,
  isInSubgroup,
  isProbablePrime,
  isScalar,
  randomScalar,
  scalarAdd,
  scalarMul,
  scalarSub,
  validateGroup,
  type PrimeOrderGroup,
} from "./elgamal/group.ts";

export {
  ElGamalError,
  addCiphertexts,
  assertValidCiphertext,
  ciphertextEquals,
  combinePublicKeys,
  decryptToGroupElement,
  encrypt,
  generateKeyPair,
  reRandomize,
  subtractPlaintext,
  type Ciphertext,
  type ElGamalKeyPair,
  type ElGamalPublicKey,
} from "./elgamal/cipher.ts";

export { DiscreteLogError, createDiscreteLogTable, discreteLogSmall } from "./elgamal/dlog.ts";

// --- Zero-knowledge proofs -------------------------------------------------

export { Transcript } from "./zkp/transcript.ts";

export {
  ProofError,
  encryptionStatement,
  proveDlogEquality,
  verifyDlogEquality,
  type DlogEqualityProof,
  type DlogEqualityStatement,
} from "./zkp/dlog-equality.ts";

export {
  proveOneOf,
  verifyOneOf,
  type DisjunctiveBranch,
  type DisjunctiveProof,
} from "./zkp/disjunctive.ts";

// --- Threshold decryption --------------------------------------------------

export {
  ShamirError,
  evaluatePolynomial,
  lagrangeCoefficient,
  reconstructSecret,
  splitSecret,
  type Share,
  type SplitResult,
} from "./threshold/shamir.ts";

export {
  DkgError,
  collectComplaints,
  computeJointPublicKey,
  computeKeyShare,
  computePublicShare,
  createDkgContribution,
  finalizeDkg,
  runDkg,
  verifyDkgShare,
  type DkgBroadcast,
  type DkgComplaint,
  type DkgContribution,
  type DkgOutcome,
} from "./threshold/dkg.ts";

export {
  TrusteeError,
  combinePartialDecryptions,
  partialDecrypt,
  publicShareFromCommitments,
  setupTrustees,
  verifyPartialDecryption,
  verifyShare,
  type PartialDecryption,
  type TrusteeKeyShare,
  type TrusteePublicShare,
  type TrusteeSetup,
} from "./threshold/trustee.ts";

// --- Election --------------------------------------------------------------

export {
  BallotError,
  createBallot,
  createBallotWithSecrets,
  generateBallotId,
  validateElectionParameters,
  verifyBallot,
  type BallotCreationOptions,
  type BallotWithSecrets,
  type ElectionParameters,
  type EncryptedBallot,
} from "./election/ballot.ts";

export {
  AuditError,
  auditAgainstCommitment,
  auditBallot,
  ballotCommitment,
  cheatSurvivalProbability,
  describeSelections,
  prepareBallot,
  type AuditResult,
  type BallotAuditSecret,
  type PreparedBallot,
} from "./election/benaloh.ts";

export {
  TallyError,
  decryptTally,
  homomorphicTally,
  type CandidateResult,
  type TallyResult,
} from "./election/tally.ts";
