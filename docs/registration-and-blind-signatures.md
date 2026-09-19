# Registration & Blind Signatures — Design Notes

Reference for the Phase 1 registration layer. Written to be defended in a viva:
every design choice below has a stated reason, and the known weaknesses are
listed rather than hidden.

---

## 0. Where eligibility comes from

D-Voting has **no external dependencies**: nothing outside this repository has to
be running, reachable, or trusted for an election to proceed.

Eligibility comes from a built-in **electoral roll**, not from identity
verification at vote time. An earlier design delegated this to an external KYC
service (document OCR + face match + liveness); replacing it was both a
dependency removal and, on reflection, a better model.

Real elections do not establish who you are at the moment you vote. They
establish it beforehand, once, and publish the result. On polling day you prove
you are an entry *on that roll*. Three consequences:

1. **Sybil resistance is structural.** The threat model's "attacker registers
   fake identities" is not mitigated, it is impossible: you cannot be on the roll
   unless the Election Commission put you there. Liveness detection can be
   fooled; a closed roll cannot be argued with.
2. **No biometrics.** The system never handles a face, a document image, or a
   date of birth. The most private data is data you never collected.
3. **No third party.** No provider to be down, breached, or subpoenaed.

### Enrolment codes

Each roll entry gets a 160-bit random code, rendered in a 32-character alphabet
that omits **I, L, O and U** — the characters people misread as 1, 1, 0 and V —
and grouped in fives, because these are typed by hand off a printed card. Input
is normalised, so a voter who types a lowercase `l` for `1` is not told they are
ineligible.

**No password hashing, deliberately.** Codes are 160-bit uniformly random, so
there is nothing to guess — an attacker cannot enumerate 2^160 no matter how fast
the hash is. Argon2/scrypt exist to slow guessing of *low-entropy human-chosen*
secrets and would only add latency here. The stored value is an HMAC under a
server-held pepper, so a database dump does not even reveal which codes are
valid, and the roll id is bound into the HMAC input so a code lifted from one
polling card cannot be replayed against another.

### The timing problem

The obvious implementation returns early when a roll id is unknown. That makes
registration an **oracle for enumerating the electorate**: submit roll numbers
with a junk code, measure the response, learn who is registered to vote.

So the verifier does the same work either way — when no entry exists it still
computes an HMAC and still runs a constant-time comparison, against a decoy hash
generated at construction. The failure is identical too: `not_eligible` covers
unknown roll id, wrong code and revoked entry alike. There is a test asserting
the responses are byte-identical.

---

## 1. The problem this layer solves

An election needs two properties that pull in opposite directions:

- **Eligibility** — only verified voters may vote, and each at most once.
- **Secrecy** — nobody, including the election authority, may learn how a
  specific voter voted.

Checking eligibility means knowing who someone is. Preserving secrecy means not
knowing. A naive system resolves this by having the authority *promise* not to
correlate its voter roll with its ballot box. That is a policy guarantee, not a
technical one — an insider, a subpoena, or a database breach dissolves it.

Blind signatures resolve it technically. The Registration Authority (RA) signs
a credential it cannot see, so the link between voter and credential does not
exist in any system, and therefore cannot be leaked, subpoenaed, or abused.

---

## 2. Protocol: RSABSSA (RFC 9474)

```
Voter (device)                                Registration Authority
──────────────                                ──────────────────────
credential ← 32 random bytes
encoded    ← PSS-Encode(credential)
r          ← random, invertible mod n
blinded    ← encoded · rᵉ mod n
                        ──── blinded ────▶
                                              verify KYC + not already issued
                                              blindSig ← blindedᵈ mod n
                        ◀─── blindSig ────
sig ← blindSig · r⁻¹ mod n
assert PSS-Verify(credential, sig)
```

Unblinding works because RSA is multiplicatively homomorphic:

```
blindSig · r⁻¹ = (encoded · rᵉ)ᵈ · r⁻¹ = encodedᵈ · rᵉᵈ · r⁻¹ = encodedᵈ · r · r⁻¹ = encodedᵈ
```

which is exactly a standard RSA-PSS signature over the credential.

### Why the unlinkability is *information-theoretic*

`r` is drawn uniformly from the invertible residues mod `n`, so `rᵉ mod n` is
also uniform, so `blinded` is uniform and **statistically independent** of
`encoded`. For any credential the voter might later present, there exists
exactly one `r` consistent with what the RA observed.

This matters: the RA's inability to link is not a computational assumption that
weakens over time or falls to a quantum computer. Even an adversary with
unbounded compute and the private key cannot link an issued credential to the
voter who requested it. The RA can only ever confirm *that it signed something*.

### Why PSS encoding, not raw blinding

This is the single most important implementation detail in this layer.

Textbook RSA satisfies `sig(a) · sig(b) = sig(a · b)`. If the protocol blinded
the *raw* credential, two voters could combine their legitimately issued
signatures to derive a valid signature on a credential that was never issued —
ballot stuffing, undetectable at the ballot box.

PSS defeats this because the product of two valid PSS encodings is not itself a
valid PSS encoding of anything. The encoding is structured (`salt`, a `0x01`
separator, zero padding, a trailing `0xbc`) and randomized, so an attacker
cannot steer the product into a well-formed encoding.

This is covered by a dedicated test — `defeats the multiplicative forgery that
breaks textbook blind RSA` in `packages/crypto/test/blind-rsa.test.ts`.

### Deterministic vs randomized variant

RFC 9474 defines a randomized variant that prepends 32 random bytes to the
message. That exists to protect *low-entropy* messages: if the message space is
small, an issuer could brute-force candidate messages against a later-revealed
signature.

D-Voting credentials are already 32 uniformly random bytes, so the message
space is 2²⁵⁶ and the prefix adds nothing. We use the deterministic variant and
document the reasoning rather than cargo-culting the randomized one.

---

## 3. The one-person-one-credential invariant

Unlinkability makes double-voting *harder to detect after the fact*, so it must
be prevented at issuance. Four layers enforce it:

1. **Database unique index** on `(election_id, identity_hash)` — the storage
   engine itself refuses two registrations for the same human.
2. **Row-level lock** — `issueCredential` runs `SELECT … FOR UPDATE` inside a
   transaction, so two concurrent requests cannot both observe "not yet issued".
   Tested by `survives a concurrent double-issuance race`.
3. **Blinded-message binding** — the SHA-256 of the signed blinded message is
   recorded. An identical retry is replayed idempotently; a *different* blinded
   message is refused with 409. This is what lets a voter whose device crashed
   mid-issuance recover, without letting an attacker harvest two credentials.
4. **Rollback on signer failure** — signing happens *inside* the transaction, so
   a signer outage rolls back the issuance rather than permanently
   disenfranchising the voter. Tested by `does not spend the issuance when
   signing fails`.

---

## 4. What the RA stores, and what it deliberately does not

| Stored | Not stored |
|---|---|
| `HMAC(pepper, electionId ‖ subjectId)` | the national ID / name / address |
| `SHA-256(blinded message)` | the credential |
| the blind signature (for idempotent retry) | the final unblinded signature |
| `credential_issued_at` timestamp | anything about any ballot |

**Why HMAC and not a plain hash.** An Aadhaar-style 12-digit number has only
~10¹² possible values; `SHA-256(id)` is reversible by exhaustive search in
seconds. HMAC under a secret pepper stored outside the database means a database
dump alone reveals nothing about who registered.

**Why the election ID is bound in.** The same person registering in two
elections produces two unrelated hashes, so RA records cannot be cross-
referenced across elections to build a participation profile. The input is
length-prefixed so `("ab","c")` and `("a","bc")` cannot collide.

**Why storing the blind signature is safe.** It is `encodedᵈ · r` for a random
`r` the RA never sees. Given a final signature, no computation links it back —
the same information-theoretic argument as above.

---

## 5. Key consistency — a subtle attack worth knowing

A malicious RA could hand *each voter a different public key*. Every credential
would still verify, but the RA would know which key went to which voter, and
could therefore tag ballots at tally time. Unlinkability falls without any
cryptography being broken.

The defence is procedural and must be stated explicitly:

- Exactly one issuer key per election.
- Its `keyId` (= `base64url(SHA-256(n ‖ e))`) is published on the bulletin board
  / blockchain genesis block.
- Clients **pin** it and recompute it locally rather than trusting the served
  value — see step 1 of `demo-voter.ts`.

---

## 6. Known limitations (stated honestly)

- **BigInt is not constant-time.** JavaScript's BigInt branches on operand
  magnitude, so the issuer's private-key operation is not side-channel hardened.
  Mitigation path: `BlindSigner` is an interface; a production deployment
  implements it against AWS KMS / CloudHSM so the key never enters process
  memory. This is a real limitation of the demo build, not a solved problem.

- **Timing correlation at the RA.** If only one voter registers in a given
  minute and one credential is spent shortly after, timing alone narrows the
  anonymity set. Blind signatures do not fix this. Real mitigations are batching
  or a mandatory delay between issuance and voting; neither is implemented in
  Phase 1.

- **The roll is an input, not a claim.** D-Voting authenticates against the
  electoral roll; it does not decide who belongs on it. Whoever compiles the roll
  is trusted to compile it honestly — an omitted voter is disenfranchised and an
  invented one gets a vote. That trust is inherent to every real election and is
  handled by scrutiny of the roll itself, not by cryptography.

- **Enrolment codes must be delivered out of band.** The security of
  registration rests on the polling card reaching the right person. Postal
  interception, or a shared household address, defeats it. This is the same
  assumption a paper poll card makes.

- **Losing the tab after registering, but before casting, loses the vote.**
  The credential and its signature live only in the browser tab's memory (see
  `voter.js`) — by design, so nothing voting-related ever touches disk. If that
  tab closes, crashes, or reloads before a ballot is cast, `/v1/register`
  refuses a second attempt for the same identity with
  `credential_already_issued`. That refusal is not a bug: reissuing a second,
  independently-blinded credential to the same person is exactly what would let
  one voter cast two mutually unlinkable ballots, breaking one-person-one-vote
  the same unlinkability is built to protect. There is no way to have both
  guarantees at once. The practical mitigation is procedural, not
  cryptographic: register and vote in one sitting, in one tab, and treat the
  confirmation screen — not the credential step — as the point of no return.
  A production UI should say this explicitly before the voter leaves the
  identify step.

- **Rate limiting is per-process and in-memory.** It does not survive a restart
  or coordinate across instances. Horizontal deployment needs Redis, or better,
  enforcement at the WAF/API gateway.

- **No formal verification.** The implementation is tested (including interop
  against OpenSSL's RSA-PSS verifier), but tested is not proven. Any binding
  real-world election use would require formal verification of the
  implementation, not just the design.

---

## 7. Test coverage map

| Property | Test |
|---|---|
| Protocol correctness | `issues a credential the voter can later prove` |
| Independent validation | `produces signatures Node accepts as standard RSA-PSS` |
| Unlinkability | `produces a different blinded message every time…` |
| Forgery resistance | `defeats the multiplicative forgery…` |
| Fault-attack defence | `blindSign` self-check (Bellcore) |
| Single issuance | `refuses a second DIFFERENT blinded message…` |
| Race safety | `survives a concurrent double-issuance race` |
| No disenfranchisement | `does not spend the issuance when signing fails` |
| Credential never stored | `never receives the credential itself` |
| Token forgery | `rejects a forged registration token` |
| Identity privacy | `does not contain the raw subject id` |
