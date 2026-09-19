# Ledger, Consensus & Public Bulletin Board

Design notes for the audit layer. As elsewhere, every choice has a stated reason
and the limitations are listed rather than hidden.

---

## 1. What the blockchain is actually for

This is the part most student blockchain-voting projects get backwards, so it is
worth stating flatly:

**The chain does not provide ballot secrecy or ballot integrity.** Those come
from the cryptographic protocol — client-side ElGamal encryption, zero-knowledge
validity proofs, threshold decryption. If you deleted the ledger entirely, votes
would still be secret and still be unforgeable.

**What the chain provides is tamper *evidence*.** Every block header commits to
its predecessor's hash, so altering or removing any recorded ballot changes
every subsequent hash and invalidates the validator signatures. An insider with
full database access can still *destroy* the ledger — but they cannot silently
*rewrite* it. "Cannot do it silently" is the entire security property.

This split is exactly what the MIT/Harvard critique (Park, Specter, Narula,
Rivest) argues for: use the blockchain for what it is good at (an immutable,
publicly auditable append-only log) and never as the source of vote secrecy.

---

## 2. Why Proof-of-Authority, not mining

An election has a fixed, known set of accountable participants: the Election
Commission and independent observer organisations. There is no anonymous
hashrate to out-compete, so open Proof-of-Work buys nothing and introduces the
51% attack surface that the team name jokes about.

PoA instead requires each block to be signed by its scheduled proposer and
attested by a quorum of named validators.

- **Round-robin proposers.** Fixing who may propose each height stops one
  validator monopolising the chain and makes an absent or misbehaving authority
  immediately visible — the gap is attributable to a named party.
- **Byzantine supermajority quorum.** The default is `⌊2n/3⌋ + 1`, so the chain
  tolerates up to `f` faulty validators where `n > 3f`. A bare majority would let
  a coalition of half the authorities rewrite records.

**Ed25519, not ECDSA.** ECDSA requires a fresh random nonce per signature;
reusing one leaks the private key outright — the failure that broke the Sony PS3
and multiple Bitcoin wallets. Ed25519 derives its nonce deterministically from
key and message, so that entire failure class does not exist. For keys that
authorise election records, removing a catastrophic-and-silent failure mode is
worth more than familiarity.

### Validators are actually independent

A quorum rule is worthless if one process holds every signing key — compromise
it and you forge all four signatures. Each `ValidatorNode` therefore holds
exactly **one** key and its **own chain replica**, and before signing anything it:

1. re-validates the block against *its own* head, not the proposer's claims;
2. re-verifies every entry through a pluggable `EntryValidator` — in D-Voting
   that means re-checking each ballot's zero-knowledge proofs, so a dishonest
   proposer cannot stuff invalid ballots past a rubber-stamp quorum;
3. refuses to sign two different blocks at the same height.

**Equivocation** is the subtle one. If a validator could be induced to attest
two different blocks at one height, an attacker could assemble two conflicting
quorums and fork the chain — showing one version of the election to some
observers and a different version to others. Nothing in the block format
prevents that; it has to be enforced by the signer. Each node records what it
attested at each height and refuses anything conflicting, while re-attesting the
*same* block idempotently so a dropped response doesn't lock it out. This is the
same safety condition proof-of-stake systems enforce by slashing.

Quorum collection tolerates a minority of unreachable or refusing validators —
which is precisely the fault tolerance the quorum exists to provide — and stops
polling as soon as the threshold is met.

### Why `propose` is authenticated and `attest` is not

These endpoints have genuinely different risk profiles, and the asymmetry is
worth being able to justify.

**`attest` is safe to leave open.** A node only signs a block that is
structurally valid *and* already signed by the scheduled proposer. An attacker
cannot fabricate something new to get attested; at worst they replay a block the
proposer really produced, and the response is identical to the legitimate one.

**`propose` is not.** Proposing makes the node sign a block *and* record that
height as attested. An attacker who could call it would make a validator commit
to a block of the attacker's choosing at height H — after which the node's own
anti-equivocation rule makes it refuse the **legitimate** block at that height.
The safety mechanism becomes a liveness attack. So `propose` requires a bearer
token, compared in constant time (a short-circuiting check would leak it a byte
at a time via response latency).

**`commit` is open**, because a block must already carry a valid quorum to be
accepted — which is exactly what makes it legitimate.

### Proposer failover (view changes)

A fixed round-robin schedule makes an absent authority visible, but it also
makes the scheduled proposer a single point of failure: if it is offline, its
round cannot proceed. Views fix that. The proposer for a height is
`(height + view) mod n`, so advancing the view hands the round to a replacement,
and after `n-1` views every validator has had a turn.

The view is part of the **signed header**, which does two things: every
validator agrees on who was entitled to propose, and the failover is permanently
visible on-chain — a chain full of `view > 0` blocks is itself evidence that an
authority is not doing its job. It cannot be edited after the fact without
invalidating every signature.

**Why advancing the view cannot fork the chain.** The obvious worry is two
different blocks both reaching quorum at one height, showing different election
records to different observers. Two properties rule it out:

1. **Quorum intersection.** The quorum is a >2/3 supermajority, so any two
   quorums share more than `n/3` validators — they cannot be disjoint.
2. **No equivocation.** A validator refuses to attest a second, different block
   at a height it has already attested.

Together, two conflicting blocks would require at least one validator to sign
both, which (2) forbids. Safety therefore holds regardless of how views advance,
which is what makes this failover sound without a full lock/unlock protocol.

The cost of rule (2) is that a view change only helps when the failed proposer
produced **no block at all** — exactly the unreachable-proposer case. If a
proposer produced a block but quorum was not gathered, the correct move is to
retry *that same block* (validators re-attest idempotently), not to advance the
view.

**View changes cannot manufacture a quorum that does not exist.** With 4
validators and a 3-of-4 quorum, one failure is survivable and two are not —
`n > 3f`. Failover fixes proposer liveness; it does not change the fault bound.

### Recovering a lagging validator

A validator that misses one commit is, without intervention, finished: its
height never advances, so every subsequent block fails its "must extend my own
chain" check and it refuses everything forever. One dropped packet would
permanently remove an authority from the set, and with a 3-of-4 quorum two such
losses stall the election.

The fix has three parts:

1. **Refusals say *why*.** A refusal caused purely by lag carries `behindAt`
   with the node's current height, distinguishing "I am behind" (recoverable)
   from "this block is wrong" (not). The distinction survives the HTTP wire.
2. **Lagging peers are replayed.** The coordinator sends the missing committed
   blocks and retries. This is safe from an untrusted coordinator because
   `commit` runs full validation — a node cannot be fed a bogus chain.
3. **Resync happens on the replication path too, not just on refusal.** This
   matters more than it looks: quorum collection stops polling as soon as the
   threshold is met, so validators beyond the quorum are never *asked* to attest
   and would never report themselves behind. They would drift further behind
   indefinitely, silently shrinking the effective validator set until a single
   failure stalled everything. Resynchronising during `broadcastCommit`, and
   before asking a node to propose, closes that.

Being *ahead* is treated as a different condition entirely and never reported as
lag — a node that has already accepted a later block must not be rewound.

### Durable storage

The chain is stored as one append-only file, one JSON block per line. The
storage shape matches the data: a chain is never updated and never deleted, so a
relational store would add an operational dependency for indexing and
transactions we barely use. A file gives three things that matter more:

- The append-only property is **structural**, not a convention — there is no
  `UPDATE` to accidentally grant.
- The whole chain is **one artefact**. An observer can copy it, walk away, and
  re-verify the entire election offline, which is what public verifiability is
  supposed to mean.
- Crash behaviour is simple enough to reason about.

`BlockStore` is unchanged, so a Postgres implementation remains a drop-in for
deployments that want one.

**Crash safety.** Appending is: write the line, `fsync`, *then* acknowledge. So
at any crash point either the record is complete and durable, or the tail is
unterminated. Only newline-terminated records count as complete; anything after
the final newline was never acknowledged and is discarded on load.

Discarding is not enough on its own — the torn tail must also be **truncated**.
Appending past an unterminated fragment splices the next block onto it and
corrupts the chain permanently. (This was a real bug, caught by the crash
recovery tests; it would have bricked a validator after any mid-append crash.)

A malformed line *anywhere else* is a hard error. Silently skipping it would let
an attacker delete a ballot by scribbling on the file. A validator also
re-verifies its whole chain at startup and **refuses to serve** if verification
fails, so a node cannot launder a corrupted chain into the quorum by starting up
and attesting from it.

### Wire format vs canonical encoding

Blocks travel as JSON but are **never hashed** as JSON. Hashing always goes
through the canonical binary encoder, precisely because JSON is not a
deterministic serialisation. Keeping the two separate means a change to the wire
format can never silently change a block hash. Parsing is strict — lengths and
types are checked at the boundary — so malformed input is rejected there rather
than becoming a confusing failure three layers in.

---

## 3. Merkle trees and the bulletin board

A voter must be able to confirm "my ballot was recorded" without downloading the
entire chain. Each block commits to its entries via a Merkle root, so inclusion
is provable from `log₂(n)` hashes — about 20 hashes for a million ballots,
verifiable on a phone in milliseconds.

The implementation follows **RFC 6962 (Certificate Transparency)**, which avoids
two well-known Merkle bugs:

**1. Second-preimage attack (leaf/node confusion).** If leaves and internal
nodes were hashed identically, an attacker could present an internal node's hash
*as a leaf*: the proof would verify and the log would appear to contain an entry
it never recorded. RFC 6962 prefixes leaves with `0x00` and internal nodes with
`0x01`, making the two hash domains disjoint.

**2. Duplicate-last-leaf malleability (Bitcoin's CVE-2012-2459).**
Implementations that pad an odd level by duplicating the final node let two
*different* leaf lists produce the *same* root — so a ledger could be rewritten
without changing its published root. RFC 6962 splits at the largest power of two
below `n` and promotes the remainder, which is injective.

Both have dedicated tests asserting the attacks fail.

### Canonical encoding

Everything is identified by its hash, so the bytes being hashed must be
reproducible by every independent verifier, forever. `JSON.stringify` is not a
specification — key order, number formatting and unicode escaping all vary. The
ledger uses a fully specified binary encoder: fixed-width big-endian integers,
every variable-length field preceded by its `u32` length. Length prefixing also
removes concatenation ambiguity, so an attacker cannot shift bytes between
fields to forge a colliding block.

---

## 4. The ballot box

A ballot is accepted only when both hold, and neither check reveals anything
about the vote or the voter:

1. **Eligibility** — the credential carries a valid RA blind signature. Since the
   RA cannot link that credential to a person, checking eligibility reveals no
   identity.
2. **Validity** — the ballot's zero-knowledge proofs show every ciphertext
   encrypts 0 or 1 and the total is in range.

Checks run cheapest-first (structure → credential → ZK proofs), so junk traffic
is rejected before consuming the expensive path.

### Credential binding

Ballot proofs are bound to the **credential fingerprint**, not just the ballot
ID. Without that, an attacker who observed a submission could re-submit the
identical ballot under their own credential, consuming the ballot ID and
blocking the real voter. With it, a ballot can only be cast by the credential
holder. Tested by `REJECTS a ballot not bound to the supplied credential`.

### Re-voting — coercion *mitigation*, not coercion *resistance*

A voter may cast any number of ballots; only the last counts, so someone under
duress can comply and quietly re-vote later.

**Be precise about this claim in the viva.** Because ballots are grouped by
credential fingerprint on a public board, a coercer watching the board can see
that the credential they coerced cast a *later* ballot. They cannot see the new
vote, but they can see that one happened. Genuine coercion resistance requires
fake credentials indistinguishable from real ones
(Juels–Catalano–Jakobsson, as implemented in Civitas) and is **not** implemented
here.

---

## 5. Tallying from the chain

The tally is computed from what is **on the chain**, not from an internal
database, and it **re-verifies every ballot** rather than trusting that the
ballot box verified correctly. An observer with only the chain and the public
keys reaches the same encrypted totals — that is what makes the result
independently checkable rather than merely asserted.

Chain order is the canonical ordering for the re-voting rule: it is what every
observer sees, and it cannot be rewritten.

---

## 6. Known limitations (stated honestly)

- **No view changes or fork choice.** This is a linear, append-only log with a
  quorum rule — not a full BFT protocol. If the scheduled proposer is offline,
  the chain stalls rather than electing a replacement. Adding PBFT-style view
  changes is the natural next step.

- **No peer discovery or gossip.** Validators are configured statically and the
  block assembler pushes to each of them. There is no membership protocol and no
  node-to-node propagation — resynchronisation flows through the coordinator
  rather than between peers.

- **Views advance on demand, not on a timeout.** The coordinator tries the next
  view as soon as a proposer fails to respond. There is no distributed timeout
  and no view-change *certificate* proving earlier views failed, so the view
  number is auditable-but-not-cryptographically-justified. A full BFT protocol
  would have validators independently time out and exchange view-change
  messages; here the coordinator drives it.

- **Validator set membership is fixed.** Adding or removing an authority
  mid-election is not supported.

- **TLS is assumed, not provided.** Validator traffic crosses organisational
  boundaries and must run over TLS — ideally mTLS, so nodes authenticate each
  other rather than relying on the propose token alone. The services speak plain
  HTTP and expect termination at a proxy.

- **In-memory block store.** Fine for the demo and for tests; the `BlockStore`
  interface exists so a Postgres or file-backed implementation can be swapped in
  without touching validation logic (which lives in the `Ledger`, not the store).

- **Ballots are stored in full on-chain.** Simple and auditable, but the chain
  grows linearly with the electorate. A production system would likely store
  ballots off-chain and commit only their hashes.

- **No network layer.** Blocks are sealed in-process. Gossip, peer discovery and
  block propagation are not implemented.

---

## 7. Test coverage map

| Property | Test |
|---|---|
| Second-preimage attack | `resists the second-preimage attack (leaf/node confusion)` |
| Merkle malleability | `resists duplicate-last-leaf malleability (Bitcoin CVE-2012-2459)` |
| Inclusion proofs at all sizes | `verifies every leaf for every tree size up to 33` |
| Truncated/extended path | `rejects a truncated path`, `rejects an over-long path` |
| Historical tampering | `DETECTS tampering with a historical block` |
| Block deletion | `DETECTS a removed block` |
| Re-signed replacement | `DETECTS a re-signed replacement block` |
| Entry replay across blocks | `DETECTS an entry replayed into a later block` |
| Faked quorum | `rejects duplicate attestations faking a quorum` |
| Rubber-stamp validators | `REFUSES a block whose entries do not match its Merkle root` |
| Invalid ballots stuffed by proposer | `applies application-level entry rules` |
| Chain forking | `REFUSES to sign two different blocks at the same height` |
| Retry safety | `re-attests the SAME block idempotently` |
| Fault tolerance | `tolerates a minority of unreachable validators` |
| Real consensus over HTTP | `seals a block by talking to four separate servers` |
| Unauthenticated propose | `REJECTS a propose request with no token` |
| Network fault tolerance | `seals despite one validator being unreachable` |
| Wire round-trip fidelity | `survives a round trip through the wire format unchanged` |
| Chain survives restart | `reloads the chain and produces the same tally` |
| Double-vote survives restart | `still refuses a ballot replayed from before the restart` |
| Torn write recovery | `discards a complete block whose trailing newline never landed` |
| Torn tail truncated | `truncates the torn tail so later appends are not spliced onto it` |
| File tampering | `REFUSES a corrupt line in the middle of the file` |
| Block deletion from file | `REFUSES a file with a deleted block` |
| Lagging node recovers | `catches a lagging validator up and still seals the block` |
| Recovery over the network | `catches up a validator that missed commits, and it attests again` |
| Catch-up is validated | `validates catch-up blocks rather than trusting the coordinator` |
| Ahead ≠ behind | `distinguishes being AHEAD from being behind` |
| Proposer failover | `advances to the next proposer when the scheduled one is offline` |
| Failover over the network | `fails over to the next proposer when the scheduled one is unreachable` |
| No fork across views | `CANNOT fork: two views at one height cannot both reach quorum` |
| View forgery | `REJECTS a proposer that is not scheduled for the claimed view` |
| View inflation | `REJECTS an out-of-range view` |
| Fault bound is honest | `cannot proceed when more than a third of validators are offline` |
| Unauthorised proposer | `rejects a block proposed by the wrong validator` |
| Post-signature stuffing | `rejects entries added after signing` |
| Credential forgery | `REJECTS a ballot with no valid credential` |
| Wrong issuer | `REJECTS a credential signed by a different Registration Authority` |
| Ballot hijacking | `REJECTS a ballot not bound to the supplied credential` |
| Re-voting rule | `counts only the LAST ballot per credential (coercion mitigation)` |
| Independent re-verification | `re-verifies every ballot rather than trusting the ballot box` |
