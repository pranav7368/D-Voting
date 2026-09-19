/**
 * @dvoting/ledger -- permissioned, hash-chained, append-only ledger.
 *
 * Provides tamper EVIDENCE for the election record. Ballot secrecy and ballot
 * integrity come from @dvoting/crypto; this package makes it impossible to
 * alter or remove a recorded ballot without the alteration being detectable by
 * any observer.
 */

export { Encoder, EncodingError, encode } from "./canonical.ts";

export {
  MerkleError,
  hashLeaf,
  hashNode,
  merkleProof,
  merkleRoot,
  verifyMerkleProof,
  type MerkleProof,
} from "./merkle.ts";

export {
  VALIDATOR_PUBLIC_KEY_BYTES,
  VALIDATOR_SIGNATURE_BYTES,
  ValidatorError,
  createValidatorSet,
  exportPrivateKey,
  findValidator,
  generateValidatorKeyPair,
  importPrivateKey,
  proposerForHeight,
  sign,
  validatorFingerprint,
  verifySignature,
  type CryptoKeyLike,
  type ValidatorIdentity,
  type ValidatorKeyPair,
  type ValidatorSet,
} from "./validator.ts";

export {
  BlockError,
  HASH_BYTES,
  ZERO_HASH,
  attest,
  blockHash,
  blockHashHex,
  buildEntryProof,
  computeEntriesRoot,
  encodeEntry,
  encodeHeader,
  proposeBlock,
  verifyAttestation,
  withAttestations,
  type Attestation,
  type Block,
  type BlockHeader,
  type LedgerEntry,
} from "./block.ts";

export {
  ChainError,
  Ledger,
  validateBlock,
  verifyChain,
  type BlockStore,
  type BlockValidationResult,
  type ChainVerificationReport,
  type EntryLocation,
} from "./chain.ts";

export { InMemoryBlockStore } from "./store.ts";

export {
  LocalValidatorPeer,
  ValidatorNode,
  ValidatorNodeError,
  collectQuorum,
  tryCollectQuorum,
  type AttestationRefusal,
  type AttestationResponse,
  type EntryValidator,
  type ProposeRequest,
  type QuorumAttempt,
  type QuorumResult,
  type ValidatorNodeOptions,
  type ValidatorPeer,
} from "./node.ts";

export {
  DistributedSealer,
  SingleProcessSealer,
  nextSealRequest,
  type BlockSealer,
  type SealRequest,
} from "./sealer.ts";

export {
  WireFormatError,
  blockFromWire,
  blockToWire,
  proposeRequestFromWire,
  proposeRequestToWire,
  type WireAttestation,
  type WireBlock,
  type WireBlockHeader,
  type WireLedgerEntry,
  type WireProposeRequest,
} from "./wire.ts";

export { HttpValidatorPeer, type HttpValidatorPeerOptions } from "./http-peer.ts";
