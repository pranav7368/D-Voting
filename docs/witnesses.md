# Witnessed bulletin board

How D-Voting makes sure every voter is looking at the **same** public record,
without trusting the ballot box that serves it.

## 1. The attack

Every verification a voter's device runs (Merkle inclusion, validator
signatures, the second-device check) reads the bulletin board through the ballot
box. Before witnesses, the device also took the **validator keys** from the
ballot box (`/v1/election`). So a dishonest box could build a private chain for
one targeted voter, sign it with keys it invented, serve those keys alongside,
and every check on that voter's device would pass. Other voters, and every
auditor, would see the real chain and never know.

This is the split-view attack. Hirschi, Schmid and Basin (CSF 2021) call the
bulletin board e-voting's "Achilles heel" for exactly this reason, and show
that a voter can only detect equivocation by cross-checking with others.

A second, related failure is **omission**: serving an auditor a board that
stops early, hiding late ballots or the published result.

## 2. The idea

Independent observers keep their own copy of the board and countersign its
current head. Voters' devices ask them **directly**.

It is the digital counterpart of polling agents signing the account of votes
recorded at a booth: an observer puts their name only to what they have seen.

## 3. The protocol

**Roster.** The commission configures witnesses (`WITNESSES`, each an id, an
Ed25519 public key and a URL) and a quorum *k*. The roster is sealed in block 0
with the rest of the election definition, so it cannot change after opening.

**Witness.** Each witness (`services/witness`) syncs from the ballot box every
few seconds. It accepts a block only if it:

- extends the chain the witness already holds (hash link to its head),
- carries a validator quorum and passes full replica validation, and
- comes from a board that has not shrunk or shown a different head at a height
  the witness has seen.

Any violation raises a **sticky alarm**: the witness stops signing and reports
the reason. Deciding that a fork was benign is a human judgement. Otherwise it
signs a checkpoint:

```
encode("dvoting/checkpoint/v1", witnessId, electionId,
       u32 height, headHash[32], genesisHash[32], witnessedAt)
```

The replica is durable (`CHAIN_PATH`) and re-verified on restart, so a witness
cannot be rolled back by restarting it.

**Device.** For a receipt in block *b*, the voter's browser or phone
(`verify-lib.js`, `gatherWitnessEvidence`):

1. reads block 0 and takes the **sealed** roster from its configuration entry,
   never from `/v1/election`;
2. fetches each witness's checkpoint from the witness's own URL;
3. fetches only block **headers** from *b* upward (`/v1/bulletin/headers`) and
   recomputes the hash links itself;
4. accepts a witness only if its signature verifies against the sealed key, it
   names this election and this genesis, its height covers *b*, and its head
   hash is reached from *b* through the recomputed links;
5. treats the receipt as witnessed when at least *k* witnesses accept.

A head the links do not reach means **that witness saw a different board**.

**Auditor.** `dvoting-verify --witnesses` requires the downloaded board to
contain every block each witness saw, exactly as they saw it. A board shorter
than a checkpoint fails ("witness saw *n* blocks, this board has only *m*"), so
omission is caught. Each witness also serves its replica in the ballot box's
own format, so the board can be downloaded from a witness instead of the box.

## 4. The election fingerprint

Block 0 seals the whole definition, witnesses included, and every checkpoint
names its hash. Twelve digits of that hash (`7593 0202 9227`) form the
**election fingerprint**, shown on the verify page, the phone page and in the
CLI. The commission and each witness publish it through their own channels.

This is the trust anchor, and it is stated plainly. A box that forges an entire
election, including a fake roster of witnesses it controls, produces a
different block 0 and therefore a **different fingerprint**. Only a human
comparison with the published value catches that case; no protocol can, because
the forger controls everything the device can reach.

## 5. What it guarantees, and what it does not

| Attack | Result | Test |
|---|---|---|
| Private board shown to one voter, real roster copied in | Every witness rejects it: different genesis | `CATCHES a private board shown to one voter` |
| History rewritten after the witnesses saw it | Rejected: head not reached from the voter's block | `CATCHES a board whose history was rewritten…` |
| Board shrinks, forks, or rewrites a seen block | Witness alarms and stops signing | `ALARMS when the board shrinks`, `…different head…`, `…does not extend…` |
| Witness restarted to forget | Replica re-verified; rollback still caught | `re-verifies its replica and still catches a rollback after restarting` |
| Impostor at a witness's address | Rejected: not the sealed key; honest quorum still met | `REJECTS a checkpoint not signed by the sealed witness key` |
| Auditor served a truncated board | Fails the omission check | `CATCHES a board that omits blocks the witnesses already saw` |
| Entire election forged with fake witnesses | Different fingerprint; caught only by comparing it | (assumption, §4) |

**Assumptions.** At least *k* witnesses are honest and reachable; the election
fingerprint is published through channels the ballot box does not control; the
device's code is the published code (bundle hashes in `public/*.sha256`).

**Not provided.** Witnesses do not make the board *correct*. Validators and the
recount do that. Witnesses make it *one* board. Liveness depends on the
witnesses being up; a device that cannot reach *k* of them reports "waiting",
never "verified".
