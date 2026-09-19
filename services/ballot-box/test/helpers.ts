import {
  LocalBlindSigner,
  MODP_2048,
  RSABSSA_SHA384_PSS_DETERMINISTIC,
  blind,
  createBallot,
  encodeElement,
  finalize,
  generateCredential,
  setupTrustees,
  toBase64Url,
  type ElectionParameters,
  type EncryptedBallot,
  type TrusteeSetup,
} from "@dvoting/crypto";
import { generateIssuerKeyPair } from "@dvoting/crypto/keygen";
import {
  DistributedSealer,
  InMemoryBlockStore,
  Ledger,
  LocalValidatorPeer,
  ValidatorNode,
  createValidatorSet,
  generateValidatorKeyPair,
  type ValidatorKeyPair,
} from "@dvoting/ledger";

import { BallotBox, credentialFingerprint, type BallotSubmission } from "../src/ballot-box.ts";

export const GROUP = MODP_2048;

export const ELECTION: ElectionParameters = {
  electionId: "ballot-box-test",
  candidates: ["Alice", "Bob", "Carol"],
  minSelections: 1,
  maxSelections: 1,
};

/** 2048-bit keys keep tests fast; production defaults are 3072-bit. */
export const issuerKeys = generateIssuerKeyPair(2048, RSABSSA_SHA384_PSS_DETERMINISTIC);

export interface Harness {
  ballotBox: BallotBox;
  trustees: TrusteeSetup;
  validatorKeys: ValidatorKeyPair[];
  nodes: ValidatorNode[];
  ledger: Ledger;
}

/**
 * Builds a genuinely distributed validator set: each node holds exactly one
 * signing key and its own chain replica, wired together in-process.
 */
export async function createHarness(
  options: {
    maxPendingBeforeSeal?: number;
    validatorCount?: number;
    /** Leave the election in `setup`. By default the harness opens the poll. */
    leaveInSetup?: boolean;
    ledger?: Ledger;
    trustees?: TrusteeSetup;
  } = {},
): Promise<Harness> {
  const validatorKeys: ValidatorKeyPair[] = [];
  for (let i = 0; i < (options.validatorCount ?? 4); i++) {
    validatorKeys.push(await generateValidatorKeyPair(i === 0 ? "election-commission" : `observer-${i}`));
  }
  const validatorSet = createValidatorSet(validatorKeys.map((k) => k.identity));

  // Each validator gets its OWN ledger replica.
  const nodes = validatorKeys.map(
    (keyPair) =>
      new ValidatorNode({
        identity: keyPair.identity,
        privateKey: keyPair.privateKey,
        ledger: new Ledger(new InMemoryBlockStore(), validatorSet, ELECTION.electionId),
      }),
  );
  const peers = nodes.map((node) => new LocalValidatorPeer(node));

  // The ballot box keeps its own replica too, and holds no signing keys at all.
  const ledger = options.ledger ?? new Ledger(new InMemoryBlockStore(), validatorSet, ELECTION.electionId);
  const trustees = options.trustees ?? setupTrustees(GROUP, 2, 3);

  const ballotBox = new BallotBox({
    election: ELECTION,
    issuerPublicKey: issuerKeys.publicKey,
    electionPublicKey: trustees.publicKey,
    trustees: {
      threshold: trustees.threshold,
      total: trustees.total,
      publicShares: trustees.publicShares.map((share) => ({
        index: share.index,
        publicShare: toBase64Url(encodeElement(GROUP, share.publicShare)),
      })),
    },
    ledger,
    sealer: new DistributedSealer(ledger, peers),
    ...(options.maxPendingBeforeSeal !== undefined
      ? { maxPendingBeforeSeal: options.maxPendingBeforeSeal }
      : {}),
  });

  await ballotBox.load();
  // Most tests are about what happens once voting is under way, so the harness
  // opens the poll unless a test is specifically exercising setup.
  if (!options.leaveInSetup && ballotBox.phase === "setup") {
    await ballotBox.openPoll();
  }

  return { ballotBox, trustees, validatorKeys, nodes, ledger };
}

/** Everything a voter does: get a credential, then build a bound ballot. */
export async function makeVoter(): Promise<{
  credential: Uint8Array;
  signature: Uint8Array;
  fingerprint: string;
}> {
  const signer = new LocalBlindSigner(issuerKeys.privateKey);
  const credential = generateCredential();
  const { blindedMessage, inverse } = await blind(issuerKeys.publicKey, credential);
  const blindSignature = await signer.blindSign(blindedMessage);
  const signature = await finalize(issuerKeys.publicKey, credential, blindSignature, inverse);
  return { credential, signature, fingerprint: await credentialFingerprint(credential) };
}

export async function makeSubmission(
  harness: Harness,
  voter: { credential: Uint8Array; signature: Uint8Array; fingerprint: string },
  selections: number[],
  election: ElectionParameters = ELECTION,
): Promise<BallotSubmission> {
  const ballot = await createBallot(election, harness.trustees.publicKey, selections, {
    credentialFingerprint: voter.fingerprint,
  });
  return {
    credential: voter.credential,
    credentialSignature: voter.signature,
    ballot,
  };
}

export type { EncryptedBallot };
